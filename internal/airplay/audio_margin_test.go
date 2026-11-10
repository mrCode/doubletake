package airplay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"testing"
	"time"
)

// marginEventsForTest feeds the guard one source-age sample every step from
// from to to (inclusive), skipping instants for which age reports ok=false (no
// frame observed then), and returns each event with its offset.
func marginEventsForTest(g *audioMarginGuard, from, to, step time.Duration, age func(time.Duration) (time.Duration, bool)) []string {
	base := time.Unix(1000, 0)
	var events []string
	for at := from; at <= to; at += step {
		frameAge, ok := age(at)
		if !ok {
			continue
		}
		switch g.observe(frameAge, base.Add(at)) {
		case audioMarginLost:
			events = append(events, fmt.Sprintf("lost@%v", at))
		case audioMarginRecovered:
			events = append(events, fmt.Sprintf("recovered@%v", at))
		}
	}
	return events
}

func constantAgeForTest(age time.Duration) func(time.Duration) (time.Duration, bool) {
	return func(time.Duration) (time.Duration, bool) { return age, true }
}

const marginStepForTest = 8 * time.Millisecond // one ALAC frame, roughly

func assertMarginEventsForTest(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
}

func TestAudioMarginGuardReportsOnceAfterOneSecondOfLostMargin(t *testing.T) {
	// 30 s of continuous lateness is one episode: one line, never repeated.
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 30*time.Second, marginStepForTest, constantAgeForTest(60*time.Millisecond))
	assertMarginEventsForTest(t, got, "lost@1s")
}

func TestAudioMarginGuardReportsRecoveryOnceWhenAgeFallsBack(t *testing.T) {
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 10*time.Second, marginStepForTest,
		func(at time.Duration) (time.Duration, bool) {
			if at < 3*time.Second {
				return 70 * time.Millisecond, true
			}
			return 15 * time.Millisecond, true
		})
	assertMarginEventsForTest(t, got, "lost@1s", "recovered@3s")
}

func TestAudioMarginGuardStartsANewEpisodeAfterRecovery(t *testing.T) {
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 10*time.Second, marginStepForTest,
		func(at time.Duration) (time.Duration, bool) {
			if at < 2*time.Second || at >= 4*time.Second {
				return 70 * time.Millisecond, true
			}
			return 15 * time.Millisecond, true
		})
	assertMarginEventsForTest(t, got, "lost@1s", "recovered@2s", "lost@5s")
}

func TestAudioMarginGuardIgnoresSpikesShorterThanOneSecond(t *testing.T) {
	// 992 ms late, then one on-time frame, repeated for 30 s.
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 30*time.Second, marginStepForTest,
		func(at time.Duration) (time.Duration, bool) {
			if at%time.Second == 992*time.Millisecond {
				return 15 * time.Millisecond, true
			}
			return 95 * time.Millisecond, true
		})
	assertMarginEventsForTest(t, got)
}

func TestAudioMarginGuardRestartsTimerWhenAgeFallsBelowThreshold(t *testing.T) {
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 3*time.Second, marginStepForTest,
		func(at time.Duration) (time.Duration, bool) {
			if at == 800*time.Millisecond {
				return 30 * time.Millisecond, true
			}
			return 70 * time.Millisecond, true
		})
	// No line for the dip either: nothing had been reported yet.
	assertMarginEventsForTest(t, got, "lost@1.808s")
}

func TestAudioMarginGuardRestartsTimerAcrossAGapInFrames(t *testing.T) {
	// Late frames either side of a 400 ms stall (no frames, or only stale ones
	// that never reach the guard) are not one continuous second of lateness.
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 3*time.Second, marginStepForTest,
		func(at time.Duration) (time.Duration, bool) {
			if at > 600*time.Millisecond && at < 1000*time.Millisecond {
				return 0, false
			}
			return 70 * time.Millisecond, true
		})
	assertMarginEventsForTest(t, got, "lost@2s")
}

func TestAudioMarginGuardToleratesAFewMissingFrames(t *testing.T) {
	// Three frame periods without a frame is ordinary delivery jitter.
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 3*time.Second, marginStepForTest,
		func(at time.Duration) (time.Duration, bool) {
			if at > 600*time.Millisecond && at < 624*time.Millisecond {
				return 0, false
			}
			return 70 * time.Millisecond, true
		})
	assertMarginEventsForTest(t, got, "lost@1s")
}

func TestAudioMarginGuardDoesNotRepeatAcrossAGapWhileStillLate(t *testing.T) {
	got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 5*time.Second, marginStepForTest,
		func(at time.Duration) (time.Duration, bool) {
			if at > 2*time.Second && at < 2500*time.Millisecond {
				return 0, false
			}
			return 70 * time.Millisecond, true
		})
	assertMarginEventsForTest(t, got, "lost@1s")
}

func TestAudioMarginGuardThresholdIsHalfThePlayoutLatency(t *testing.T) {
	if got := marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 3*time.Second, marginStepForTest, constantAgeForTest(50*time.Millisecond)); len(got) != 0 {
		t.Fatalf("age exactly half the 100 ms budget: events %v, want none", got)
	}
	assertMarginEventsForTest(t, marginEventsForTest(newAudioMarginGuard(4410, 352), 0, 3*time.Second, marginStepForTest, constantAgeForTest(51*time.Millisecond)), "lost@1s")
	if got := marginEventsForTest(newAudioMarginGuard(8820, 352), 0, 3*time.Second, marginStepForTest, constantAgeForTest(90*time.Millisecond)); len(got) != 0 {
		t.Fatalf("90 ms age with a 200 ms budget: events %v, want none", got)
	}
	if got := marginEventsForTest(newAudioMarginGuard(0, 352), 0, 3*time.Second, marginStepForTest, constantAgeForTest(time.Second)); len(got) != 0 {
		t.Fatalf("zero playout budget: events %v, want none", got)
	}
}

func TestAudioMarginLogLines(t *testing.T) {
	logged := captureLogForTest(t, func() {
		logAudioMargin(audioMarginNone, 70*time.Millisecond, 4410)
		logAudioMargin(audioMarginLost, 63*time.Millisecond+400*time.Microsecond, 4410)
		logAudioMargin(audioMarginRecovered, 12*time.Millisecond, 4410)
	})
	lines := strings.Split(strings.TrimSpace(logged), "\n")
	want := []string{
		"[AUDIO] audio is arriving 63ms late (margin 37ms of 100ms); the delay is before the helper",
		"[AUDIO] playout margin recovered",
	}
	if len(lines) != len(want) {
		t.Fatalf("log = %q, want %q", logged, want)
	}
	for i := range want {
		if !strings.HasSuffix(lines[i], want[i]) {
			t.Fatalf("log line %d = %q, want it to end %q", i, lines[i], want[i])
		}
	}
}

// agedTimestampedPCMFramesForTest returns frames whose source-age at read time
// follows ages[i]; source positions advance by one codec frame per read.
type agedTimestampedPCMFramesForTest struct {
	ages []time.Duration
	read int
	spf  uint32
}

func (r *agedTimestampedPCMFramesForTest) ReadPCMFrame(dst []byte) (time.Time, error) {
	position, err := r.ReadPCMFramePosition(dst)
	return position.PTS, err
}

func (r *agedTimestampedPCMFramesForTest) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	if r.read == len(r.ages) {
		return audioPCMFramePosition{}, io.EOF
	}
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

func TestStreamAudioNeverDropsLateButPlayableFrames(t *testing.T) {
	ms := time.Millisecond
	// A 1 s playout budget leaves wide margins either side of the 500 ms
	// threshold, so scheduler stalls cannot change which frames count as late.
	var ages []time.Duration
	for range 5 {
		ages = append(ages, 1*ms)
	}
	for range 20 {
		ages = append(ages, 700*ms) // late, still 300 ms before its deadline
	}
	for range 5 {
		ages = append(ages, 1*ms)
	}
	reader := &agedTimestampedPCMFramesForTest{ages: ages, spf: 352}
	var stream *AudioStream
	var packets [][]byte
	logged := captureLogForTest(t, func() {
		stream, packets = streamAudioPacketsWithStreamForTest(t, "plaintext", reader, AudioCodecALAC, func(stream *AudioStream) {
			// This capture is read as fast as the loop runs; report at the second
			// late frame instead of after a second of them, and never treat a
			// scheduler stall as a gap.
			guard := newAudioMarginGuard(stream.latencySamples, uint32(stream.spf))
			guard.sustain = time.Nanosecond
			guard.maxGap = time.Hour
			stream.marginGuard = guard
		})
	})
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
	if n := strings.Count(logged, "[AUDIO] audio is arriving "); n != 1 {
		t.Fatalf("log = %q, want the late-audio line once, got %d", logged, n)
	}
	if !regexp.MustCompile(`\[AUDIO\] audio is arriving 7[0-9][0-9]ms late \(margin [0-9]+ms of 1s\); the delay is before the helper`).MatchString(logged) {
		t.Fatalf("log = %q, want the late-audio line with its age and margin", logged)
	}
	if n := strings.Count(logged, "[AUDIO] playout margin recovered"); n != 1 {
		t.Fatalf("log = %q, want the recovery line once, got %d", logged, n)
	}
	if strings.Index(logged, "audio is arriving") > strings.Index(logged, "playout margin recovered") {
		t.Fatalf("log = %q, want the recovery after the late line", logged)
	}
}
