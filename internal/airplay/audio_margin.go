package airplay

import (
	"log"
	"time"
)

// The receiver plays each audio frame a fixed playout latency after its source
// PTS, so playout lead = latency - source-age. When something before the send
// loop starts holding audio back, every frame arrives later and the lead
// shrinks; at about 40 ms left an Apple TV turns robotic, and with none left it
// goes silent. These thresholds decide when the margin counts as lost and how
// far a skip goes to win it back.
const (
	// audioMarginLostFor is how long source-age must stay above half the
	// playout latency before a skip. Ordinary jitter is far shorter.
	audioMarginLostFor = time.Second
	// audioMarginSkipCooldown separates skips, so a delay the helper cannot
	// remove does not keep cutting holes into the audio.
	audioMarginSkipCooldown = 5 * time.Second
	// audioMarginFreshAge is the source-age at which a skip stops discarding.
	audioMarginFreshAge = 20 * time.Millisecond
)

// audioMarginGuard watches the source-age of sent frames and says when to skip
// ahead: once age has stayed above half the playout latency for sustain, and
// not again until cooldown has passed. It is pure; StreamAudio feeds it.
type audioMarginGuard struct {
	threshold time.Duration
	sustain   time.Duration
	cooldown  time.Duration
	highSince time.Time
	lastSkip  time.Time
}

func newAudioMarginGuard(latencySamples uint32) *audioMarginGuard {
	return &audioMarginGuard{
		threshold: audioLatencyDuration(latencySamples) / 2,
		sustain:   audioMarginLostFor,
		cooldown:  audioMarginSkipCooldown,
	}
}

// observe records the source-age of a frame about to be sent at now. It
// reports whether to skip ahead, and for how long age has been continuously
// above the threshold (a skip does not restart that clock).
func (g *audioMarginGuard) observe(age time.Duration, now time.Time) (skip bool, lateFor time.Duration) {
	if g.threshold <= 0 || age <= g.threshold {
		g.highSince = time.Time{}
		return false, 0
	}
	if g.highSince.IsZero() {
		g.highSince = now
	}
	lateFor = now.Sub(g.highSince)
	if lateFor < g.sustain {
		return false, lateFor
	}
	if !g.lastSkip.IsZero() && now.Sub(g.lastSkip) < g.cooldown {
		return false, lateFor
	}
	g.lastSkip = now
	return true, lateFor
}

// freshAge is the source-age at which a skip stops. It never exceeds the
// trigger threshold, so a skip cannot end on a frame that still counts as late.
func (g *audioMarginGuard) freshAge() time.Duration {
	if g.threshold < audioMarginFreshAge {
		return g.threshold
	}
	return audioMarginFreshAge
}

// audioBacklogSkip is the outcome of skipAudioBacklog.
type audioBacklogSkip struct {
	// n and position describe the last frame read, which the caller sends.
	n        int
	position audioPCMFramePosition
	age      time.Duration
	// discarded counts the frames dropped, including the one in hand when the
	// skip began. Zero means nothing was queued behind that frame: the caller
	// sends it, then this one.
	discarded int
	// restored reports that the returned frame is fresh.
	restored bool
}

// skipAudioBacklog discards queued capture frames, starting with the frame in
// hand, until a frame is fresh, a read has to wait for the next live frame (the
// queue is empty), or limit worth of audio has been discarded: a queue cannot
// hold more audio than the frame in hand was late, so a capture that never
// yields a fresh frame cannot swallow audio indefinitely. Frames are dropped
// whole, so the source positions jump forward and the RTP clock maps the gap
// exactly as it maps the stale-frame path's drops.
func skipAudioBacklog(read func() (int, audioPCMFramePosition, error), now func() time.Time, frameDuration, freshAge, limit time.Duration) (audioBacklogSkip, error) {
	discarded := 0
	for {
		started := now()
		n, position, err := read()
		if err != nil {
			return audioBacklogSkip{discarded: discarded}, err
		}
		finished := now()
		if n == 0 {
			continue
		}
		age := finished.Sub(position.PTS)
		// A read that blocks for half a codec frame found the queue empty and
		// waited for the next live frame.
		empty := finished.Sub(started) >= frameDuration/2
		if discarded == 0 && empty {
			// Nothing was queued behind the frame in hand. Dropping it would
			// only punch a hole in the audio without gaining any margin.
			return audioBacklogSkip{n: n, position: position, age: age, restored: age < freshAge}, nil
		}
		discarded++
		if age < freshAge || empty || time.Duration(discarded)*frameDuration >= limit {
			return audioBacklogSkip{n: n, position: position, age: age, discarded: discarded, restored: age < freshAge}, nil
		}
	}
}

func logAudioMarginSkip(age, lateFor time.Duration, skip audioBacklogSkip, frameDuration time.Duration) {
	age = age.Round(time.Millisecond)
	lateFor = lateFor.Round(time.Millisecond)
	now := skip.age.Round(time.Millisecond)
	switch {
	case skip.discarded == 0:
		log.Printf("[AUDIO] audio arrived %v late for %v; nothing was queued to skip, so the delay is before the helper (still %v late)",
			age, lateFor, now)
	case skip.restored:
		log.Printf("[AUDIO] audio arrived %v late for %v; skipped ahead to restore the playout margin", age, lateFor)
	default:
		log.Printf("[AUDIO] audio arrived %v late for %v; skipped %v of queued audio but it is still %v late",
			age, lateFor, (time.Duration(skip.discarded) * frameDuration).Round(time.Millisecond), now)
	}
	dbg("[AUDIO] margin skip discarded %d frames (%v); resuming at source-age %v",
		skip.discarded, (time.Duration(skip.discarded) * frameDuration).Round(time.Millisecond), now)
}
