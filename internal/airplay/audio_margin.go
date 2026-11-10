package airplay

import (
	"log"
	"time"
)

// The receiver plays each audio frame a fixed playout latency after its source
// PTS, so playout lead = latency - source-age. When something before the send
// loop starts holding audio back, every frame arrives later and the lead
// shrinks: at about 40 ms left an Apple TV turns robotic, and with none left it
// goes silent. The send loop reads as fast as frames arrive, so a backlog in
// its own read path drains by itself; a lasting loss of lead is a delay before
// the helper, which dropping frames cannot undo. The guard therefore only
// reports it, once per episode, so a hardware log says where the delay is.
const (
	// audioMarginLostFor is how long source-age must stay above half the
	// playout latency before it is reported. Ordinary jitter is far shorter.
	audioMarginLostFor = time.Second
	// audioMarginMaxGapFrames is how many frame periods may pass without an
	// observed frame (a stall, or a run of stale frames) before the lateness
	// counts as interrupted and its timer restarts.
	audioMarginMaxGapFrames = 4
)

type audioMarginEvent int

const (
	audioMarginNone audioMarginEvent = iota
	// audioMarginLost: source-age has stayed above the threshold for sustain.
	audioMarginLost
	// audioMarginRecovered: source-age fell back after a reported loss.
	audioMarginRecovered
)

// audioMarginGuard watches the source-age of frames about to be sent. It is
// pure; StreamAudio feeds it and logs its events.
type audioMarginGuard struct {
	threshold time.Duration
	sustain   time.Duration
	maxGap    time.Duration

	highSince    time.Time
	lastObserved time.Time
	reported     bool
}

func newAudioMarginGuard(latencySamples, frameSamples uint32) *audioMarginGuard {
	return &audioMarginGuard{
		threshold: audioLatencyDuration(latencySamples) / 2,
		sustain:   audioMarginLostFor,
		maxGap:    audioMarginMaxGapFrames * audioSamplesDuration(uint64(frameSamples)),
	}
}

// observe records the source-age of a frame about to be sent at now and
// returns at most one event per change of state: Lost once age has stayed
// above the threshold for sustain without a gap longer than maxGap, then
// nothing until age falls back to the threshold or below, which is Recovered.
func (g *audioMarginGuard) observe(age time.Duration, now time.Time) audioMarginEvent {
	if g.threshold <= 0 {
		return audioMarginNone
	}
	gap := !g.lastObserved.IsZero() && now.Sub(g.lastObserved) > g.maxGap
	g.lastObserved = now
	if age <= g.threshold {
		g.highSince = time.Time{}
		if g.reported {
			g.reported = false
			return audioMarginRecovered
		}
		return audioMarginNone
	}
	if g.highSince.IsZero() || gap {
		g.highSince = now
	}
	if !g.reported && now.Sub(g.highSince) >= g.sustain {
		g.reported = true
		return audioMarginLost
	}
	return audioMarginNone
}

// logAudioMargin prints the line for a guard event; audioMarginNone prints
// nothing.
func logAudioMargin(event audioMarginEvent, age time.Duration, latencySamples uint32) {
	switch event {
	case audioMarginLost:
		latency := audioLatencyDuration(latencySamples)
		log.Printf("[AUDIO] audio is arriving %v late (margin %v of %v); the delay is before the helper",
			age.Round(time.Millisecond), (latency - age).Round(time.Millisecond), latency.Round(time.Millisecond))
	case audioMarginRecovered:
		log.Printf("[AUDIO] playout margin recovered")
	}
}
