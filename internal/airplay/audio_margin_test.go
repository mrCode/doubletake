package airplay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"testing"
	"time"
)

// observeAudioMarginForTest feeds the guard one source-age sample every step
// from start to end (inclusive) and returns the offsets at which it skipped.
func observeAudioMarginForTest(g *audioMarginGuard, base time.Time, from, to, step time.Duration, age func(time.Duration) time.Duration) []time.Duration {
	var skips []time.Duration
	for at := from; at <= to; at += step {
		if skip, _ := g.observe(age(at), base.Add(at)); skip {
			skips = append(skips, at)
		}
	}
	return skips
}

func TestAudioMarginGuardSkipsOnceAfterOneSecondOfLostMargin(t *testing.T) {
	g := newAudioMarginGuard(4410) // 100 ms playout budget
	base := time.Unix(1000, 0)
	for at := time.Duration(0); at < time.Second; at += 10 * time.Millisecond {
		if skip, _ := g.observe(60*time.Millisecond, base.Add(at)); skip {
			t.Fatalf("skipped after only %v above half the playout budget", at)
		}
	}
	skip, lateFor := g.observe(60*time.Millisecond, base.Add(time.Second))
	if !skip {
		t.Fatal("did not skip after 1 s with source-age above half the playout budget")
	}
	if lateFor != time.Second {
		t.Fatalf("late-for = %v, want 1s", lateFor)
	}
	more := observeAudioMarginForTest(g, base, time.Second+10*time.Millisecond, 2*time.Second, 10*time.Millisecond,
		func(time.Duration) time.Duration { return 60 * time.Millisecond })
	if len(more) != 0 {
		t.Fatalf("skipped again at %v, want one skip", more)
	}
}

func TestAudioMarginGuardWaitsForCooldownBetweenSkips(t *testing.T) {
	g := newAudioMarginGuard(4410)
	base := time.Unix(1000, 0)
	var skips []time.Duration
	var lateFor []time.Duration
	for at := time.Duration(0); at <= 12*time.Second; at += 10 * time.Millisecond {
		if skip, late := g.observe(90*time.Millisecond, base.Add(at)); skip {
			skips = append(skips, at)
			lateFor = append(lateFor, late)
		}
	}
	want := []time.Duration{time.Second, 6 * time.Second, 11 * time.Second}
	if fmt.Sprint(skips) != fmt.Sprint(want) {
		t.Fatalf("skips at %v, want %v", skips, want)
	}
	// Late-for counts from when the audio first fell behind, across skips.
	if fmt.Sprint(lateFor) != fmt.Sprint(want) {
		t.Fatalf("late-for at each skip = %v, want %v", lateFor, want)
	}
}

func TestAudioMarginGuardIgnoresSpikesShorterThanOneSecond(t *testing.T) {
	g := newAudioMarginGuard(4410)
	// 990 ms late, then one on-time frame, repeated for 30 s.
	skips := observeAudioMarginForTest(g, time.Unix(1000, 0), 0, 30*time.Second, 10*time.Millisecond,
		func(at time.Duration) time.Duration {
			if at%time.Second == 990*time.Millisecond {
				return 15 * time.Millisecond
			}
			return 95 * time.Millisecond
		})
	if len(skips) != 0 {
		t.Fatalf("short spikes triggered skips at %v", skips)
	}
}

func TestAudioMarginGuardRestartsTimerWhenAgeFallsBelowThreshold(t *testing.T) {
	g := newAudioMarginGuard(4410)
	skips := observeAudioMarginForTest(g, time.Unix(1000, 0), 0, 3*time.Second, 10*time.Millisecond,
		func(at time.Duration) time.Duration {
			if at == 810*time.Millisecond {
				return 30 * time.Millisecond
			}
			return 70 * time.Millisecond
		})
	if len(skips) != 1 || skips[0] != 1820*time.Millisecond {
		t.Fatalf("skips at %v, want one at 1.82s (1 s after the age rose again)", skips)
	}
}

func TestAudioMarginGuardThresholdIsHalfThePlayoutLatency(t *testing.T) {
	constant := func(age time.Duration) func(time.Duration) time.Duration {
		return func(time.Duration) time.Duration { return age }
	}
	base := time.Unix(1000, 0)
	if skips := observeAudioMarginForTest(newAudioMarginGuard(4410), base, 0, 3*time.Second, 10*time.Millisecond, constant(50*time.Millisecond)); len(skips) != 0 {
		t.Fatalf("age exactly half the 100 ms budget skipped at %v", skips)
	}
	if skips := observeAudioMarginForTest(newAudioMarginGuard(4410), base, 0, 3*time.Second, 10*time.Millisecond, constant(51*time.Millisecond)); len(skips) != 1 {
		t.Fatalf("age just above half the 100 ms budget skipped at %v, want once", skips)
	}
	if skips := observeAudioMarginForTest(newAudioMarginGuard(8820), base, 0, 3*time.Second, 10*time.Millisecond, constant(90*time.Millisecond)); len(skips) != 0 {
		t.Fatalf("90 ms age with a 200 ms budget skipped at %v", skips)
	}
	if skips := observeAudioMarginForTest(newAudioMarginGuard(0), base, 0, 3*time.Second, 10*time.Millisecond, constant(time.Second)); len(skips) != 0 {
		t.Fatalf("a zero playout budget skipped at %v", skips)
	}
}

func TestAudioMarginGuardFreshAgeIsTwentyMillisecondsWithinTheBudget(t *testing.T) {
	if got := newAudioMarginGuard(4410).freshAge(); got != 20*time.Millisecond {
		t.Fatalf("fresh age at a 100 ms budget = %v, want 20ms", got)
	}
	// A budget so small that half of it is under 20 ms: fresh must still be
	// below the trigger threshold, or a skip could stop on a frame that is late.
	if got, threshold := newAudioMarginGuard(882).freshAge(), audioLatencyDuration(882)/2; got != threshold {
		t.Fatalf("fresh age at a 20 ms budget = %v, want the %v threshold", got, threshold)
	}
}

// scriptedAudioBacklog is a capture queue on a fake clock: each read takes
// wait, then returns a frame that is age old.
type scriptedAudioBacklog struct {
	clock  time.Time
	frames []scriptedAudioFrame
	reads  int
}

type scriptedAudioFrame struct {
	age  time.Duration
	wait time.Duration
}

func (b *scriptedAudioBacklog) now() time.Time { return b.clock }

func (b *scriptedAudioBacklog) read() (int, audioPCMFramePosition, error) {
	if b.reads == len(b.frames) {
		return 0, audioPCMFramePosition{}, io.EOF
	}
	frame := b.frames[b.reads]
	b.reads++
	b.clock = b.clock.Add(frame.wait)
	return 100 + b.reads, audioPCMFramePosition{PTS: b.clock.Add(-frame.age), SourceRTP: uint32(b.reads) * 352, HasSourceRTP: true}, nil
}

const scriptedAudioFrameDuration = 8 * time.Millisecond

func TestSkipAudioBacklogDiscardsQueuedFramesUntilOneIsFresh(t *testing.T) {
	backlog := &scriptedAudioBacklog{clock: time.Unix(1000, 0)}
	for _, age := range []time.Duration{72, 64, 56, 48, 40, 32, 24, 16, 8} {
		backlog.frames = append(backlog.frames, scriptedAudioFrame{age: age * time.Millisecond})
	}
	got, err := skipAudioBacklog(backlog.read, backlog.now, scriptedAudioFrameDuration, 20*time.Millisecond, 80*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	// The frame in hand plus the 72..24 ms frames are discarded; 16 ms is fresh.
	if got.discarded != 8 || got.age != 16*time.Millisecond || !got.restored || got.n != 108 {
		t.Fatalf("skip = %+v, want 8 discarded and the 16 ms frame (n=108) kept as restored", got)
	}
	if backlog.reads != 8 {
		t.Fatalf("read %d frames, want to stop at the first fresh one (8)", backlog.reads)
	}
}

func TestSkipAudioBacklogStopsWhenTheQueueRunsDry(t *testing.T) {
	backlog := &scriptedAudioBacklog{clock: time.Unix(1000, 0), frames: []scriptedAudioFrame{
		{age: 72 * time.Millisecond},
		{age: 64 * time.Millisecond},
		// Nothing more is queued: this read waits for the next live frame.
		{age: 62 * time.Millisecond, wait: scriptedAudioFrameDuration},
		{age: 10 * time.Millisecond},
	}}
	got, err := skipAudioBacklog(backlog.read, backlog.now, scriptedAudioFrameDuration, 20*time.Millisecond, 80*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.discarded != 3 || got.n != 103 || got.restored {
		t.Fatalf("skip = %+v, want 3 discarded and the frame that had to be waited for (n=103), not restored", got)
	}
	if backlog.reads != 3 {
		t.Fatalf("read %d frames, want to stop once a read had to wait (3)", backlog.reads)
	}
}

func TestSkipAudioBacklogKeepsTheFrameInHandWhenNothingIsQueued(t *testing.T) {
	// The delay is before the queue: the very first read waits. Discarding the
	// frame in hand would only punch a hole without gaining any margin.
	backlog := &scriptedAudioBacklog{clock: time.Unix(1000, 0), frames: []scriptedAudioFrame{
		{age: 90 * time.Millisecond, wait: scriptedAudioFrameDuration},
	}}
	got, err := skipAudioBacklog(backlog.read, backlog.now, scriptedAudioFrameDuration, 20*time.Millisecond, 90*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.discarded != 0 || got.n != 101 || got.restored {
		t.Fatalf("skip = %+v, want nothing discarded and the next frame returned to send after the one in hand", got)
	}
}

func TestSkipAudioBacklogDiscardsAtMostTheLateAudio(t *testing.T) {
	// A queue that never yields a fresh frame must not swallow audio forever:
	// a backlog cannot hold more audio than the frame in hand was late.
	backlog := &scriptedAudioBacklog{clock: time.Unix(1000, 0)}
	for range 100 {
		backlog.frames = append(backlog.frames, scriptedAudioFrame{age: 80 * time.Millisecond})
	}
	got, err := skipAudioBacklog(backlog.read, backlog.now, scriptedAudioFrameDuration, 20*time.Millisecond, 80*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.discarded != 10 || got.restored || backlog.reads != 10 {
		t.Fatalf("skip = %+v after %d reads, want 10 frames (80 ms) discarded, not restored", got, backlog.reads)
	}
}

func TestSkipAudioBacklogReturnsReadErrors(t *testing.T) {
	backlog := &scriptedAudioBacklog{clock: time.Unix(1000, 0), frames: []scriptedAudioFrame{{age: 80 * time.Millisecond}}}
	if _, err := skipAudioBacklog(backlog.read, backlog.now, scriptedAudioFrameDuration, 20*time.Millisecond, 80*time.Millisecond); !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want the capture's EOF", err)
	}
}

// agedTimestampedPCMFramesForTest returns frames whose source-age at read time
// follows ages[i]; source positions advance by one codec frame per read.
type agedTimestampedPCMFramesForTest struct {
	ages  []time.Duration
	waits map[int]time.Duration // reads that block, as on an empty queue
	read  int
	spf   uint32
}

func (r *agedTimestampedPCMFramesForTest) ReadPCMFrame(dst []byte) (time.Time, error) {
	position, err := r.ReadPCMFramePosition(dst)
	return position.PTS, err
}

func (r *agedTimestampedPCMFramesForTest) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	if r.read == len(r.ages) {
		return audioPCMFramePosition{}, io.EOF
	}
	time.Sleep(r.waits[r.read])
	position := audioPCMFramePosition{
		PTS:          time.Now().Add(-r.ages[r.read]),
		SourceRTP:    uint32(r.read) * r.spf,
		HasSourceRTP: true,
	}
	fillAgedFramePCMForTest(dst, r.read)
	r.read++
	return position, nil
}

// fillAgedFramePCMForTest gives every source frame distinct samples, so a sent
// payload identifies the frame it was encoded from.
func fillAgedFramePCMForTest(dst []byte, frame int) {
	for i := 0; i+1 < len(dst); i += 2 {
		binary.LittleEndian.PutUint16(dst[i:], uint16(frame*997+i*7))
	}
}

// assertSentAudioPayloadsMatchSourceFramesForTest checks that each sequence
// carries the ALAC encoding of the source frame its RTP timestamp names.
func assertSentAudioPayloadsMatchSourceFramesForTest(t *testing.T, stream *AudioStream, packets [][]byte, spf uint32) {
	t.Helper()
	firstRTP := binary.BigEndian.Uint32(packets[0][4:8])
	pcm := make([]byte, int(spf)*audioBytesPerSampleFrame)
	want := make([]byte, 8192)
	for _, packet := range packets {
		frame := int((binary.BigEndian.Uint32(packet[4:8]) - firstRTP) / spf)
		fillAgedFramePCMForTest(pcm, frame)
		n := (&alacEncoder{}).Encode(want, pcm)
		if got := decodeAudioPacketPayloadForTest(t, stream, "plaintext", packet); !bytes.Equal(got, want[:n]) {
			t.Fatalf("sequence %d (source frame %d) carries another frame's audio", binary.BigEndian.Uint16(packet[2:4]), frame)
		}
	}
}

func lateAudioScriptForTest() []time.Duration {
	ms := time.Millisecond
	ages := []time.Duration{11 * ms, 11 * ms, 11 * ms, 11 * ms, 11 * ms} // frames 0-4: on time
	ages = append(ages, 80*ms, 80*ms, 80*ms)                             // frames 5-7: suddenly 80 ms old
	ages = append(ages, 72*ms, 64*ms, 56*ms, 48*ms, 40*ms, 32*ms, 24*ms) // frames 8-14: the rest of the backlog
	for range 10 {
		ages = append(ages, 12*ms) // frames 15-24: fresh again
	}
	return ages
}

// sentAudioSourceFramesForTest returns, in sequence order, which source frame
// (RTP offset / spf) each distinct sequence number carried.
func sentAudioSourceFramesForTest(t *testing.T, packets [][]byte, spf uint32) []uint32 {
	t.Helper()
	if len(packets) == 0 {
		t.Fatal("no audio packets were sent")
	}
	firstRTP := binary.BigEndian.Uint32(packets[0][4:8])
	bySeq := map[uint16]uint32{}
	maxSeq := uint16(0)
	for _, packet := range packets {
		seq := binary.BigEndian.Uint16(packet[2:4])
		bySeq[seq] = (binary.BigEndian.Uint32(packet[4:8]) - firstRTP) / spf
		maxSeq = max(maxSeq, seq)
	}
	frames := make([]uint32, 0, maxSeq)
	for seq := uint16(1); seq <= maxSeq; seq++ {
		frame, ok := bySeq[seq]
		if !ok {
			t.Fatalf("sequence %d was never sent; sequences must stay continuous", seq)
		}
		frames = append(frames, frame)
	}
	return frames
}

// captureLogForTest returns everything the standard logger prints during fn.
func captureLogForTest(t *testing.T, fn func()) string {
	t.Helper()
	var out bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(previous)
	fn()
	return out.String()
}

// quickMarginGuardForTest keeps production thresholds but skips on the second
// late frame: these captures are read as fast as the loop runs, so the real
// one-second wait would need a second of fake audio per test.
func quickMarginGuardForTest(stream *AudioStream) {
	stream.latencySamples = 4410
	guard := newAudioMarginGuard(stream.latencySamples)
	guard.sustain = time.Nanosecond
	stream.marginGuard = guard
}

func TestStreamAudioSkipsAheadWhenAudioStaysLate(t *testing.T) {
	reader := &agedTimestampedPCMFramesForTest{ages: lateAudioScriptForTest(), spf: 352}
	var stream *AudioStream
	var packets [][]byte
	logged := captureLogForTest(t, func() {
		stream, packets = streamAudioPacketsWithStreamForTest(t, "plaintext", reader, AudioCodecALAC, quickMarginGuardForTest)
	})
	// The age is whatever the scheduler made of 80 ms; only the shape is fixed.
	if strings.Count(logged, "skipped ahead to restore the playout margin") != 1 ||
		!regexp.MustCompile(`\[AUDIO\] audio arrived (79|8[0-9])ms late for [0-9.]+[mµn]?s; skipped ahead`).MatchString(logged) {
		t.Fatalf("log = %q, want one skip-ahead line", logged)
	}
	got := sentAudioSourceFramesForTest(t, packets, 352)
	// Frame 5 starts the late run and is sent; frame 6 triggers the skip, which
	// discards 6-14 and resumes at the first fresh frame, then keeps sending.
	want := []uint32{0, 1, 2, 3, 4, 5, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
	if len(got) != len(want) {
		t.Fatalf("sent source frames %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sent source frames %v, want %v", got, want)
		}
	}
	assertSentAudioPayloadsMatchSourceFramesForTest(t, stream, packets, 352)
}

func TestStreamAudioSendsEveryFrameThroughAShortLateSpike(t *testing.T) {
	reader := &agedTimestampedPCMFramesForTest{ages: lateAudioScriptForTest(), spf: 352}
	stream, packets := streamAudioPacketsWithStreamForTest(t, "plaintext", reader, AudioCodecALAC, func(stream *AudioStream) {
		stream.latencySamples = 4410 // the default guard: 1 s of lateness before any skip
	})
	got := sentAudioSourceFramesForTest(t, packets, 352)
	if len(got) != len(reader.ages) {
		t.Fatalf("sent source frames %v, want all %d frames", got, len(reader.ages))
	}
	for i, frame := range got {
		if frame != uint32(i) {
			t.Fatalf("sent source frames %v, want every frame in order", got)
		}
	}
	assertSentAudioPayloadsMatchSourceFramesForTest(t, stream, packets, 352)
}

func TestStreamAudioKeepsEveryFrameWhenNothingIsQueuedToSkip(t *testing.T) {
	ms := time.Millisecond
	ages := []time.Duration{11 * ms, 11 * ms, 11 * ms, 11 * ms, 11 * ms}
	for range 8 {
		ages = append(ages, 80*ms) // frames 5-12: late, but nothing queued behind them
	}
	// The skip triggers on frame 6; reading frame 7 has to wait for it to be
	// captured, so the delay is upstream and there is no backlog to drop.
	reader := &agedTimestampedPCMFramesForTest{ages: ages, spf: 352, waits: map[int]time.Duration{7: 10 * ms}}
	var stream *AudioStream
	var packets [][]byte
	logged := captureLogForTest(t, func() {
		stream, packets = streamAudioPacketsWithStreamForTest(t, "plaintext", reader, AudioCodecALAC, quickMarginGuardForTest)
	})
	if !strings.Contains(logged, "nothing was queued to skip") || strings.Contains(logged, "skipped ahead") {
		t.Fatalf("log = %q, want the nothing-queued line and no skip", logged)
	}
	got := sentAudioSourceFramesForTest(t, packets, 352)
	if len(got) != len(ages) {
		t.Fatalf("sent source frames %v, want all %d frames", got, len(ages))
	}
	for i, frame := range got {
		if frame != uint32(i) {
			t.Fatalf("sent source frames %v, want every frame in order", got)
		}
	}
	assertSentAudioPayloadsMatchSourceFramesForTest(t, stream, packets, 352)
}
