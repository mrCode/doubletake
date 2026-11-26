package airplay

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseAVOffset(t *testing.T) {
	for _, test := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{in: "120\n", want: 120 * time.Millisecond, ok: true},
		{in: " -80 ", want: -80 * time.Millisecond, ok: true},
		{in: "+40", want: 40 * time.Millisecond, ok: true},
		{in: "0", want: 0, ok: true},
		{in: "5000", want: AVOffsetLimit, ok: true},
		{in: "-5000", want: -AVOffsetLimit, ok: true},
		{in: "abc"},
		{in: "1.5"},
		{in: ""},
	} {
		got, ok := parseAVOffset([]byte(test.in))
		if got != test.want || ok != test.ok {
			t.Errorf("parseAVOffset(%q) = %v, %v; want %v, %v", test.in, got, ok, test.want, test.ok)
		}
	}
}

func writeOffset(t *testing.T, path, value string, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	// Distinct modification times, as successive slider writes have.
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestAVOffsetSourceFollowsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offset")
	source := newAVOffsetSource(path)
	start := time.Now()
	at := func(d time.Duration) time.Duration { return source.at(start.Add(d)) }

	if got := at(0); got != 0 {
		t.Fatalf("no file: %v, want 0", got)
	}

	writeOffset(t, path, "150", start.Add(time.Second))
	if got := at(100 * time.Millisecond); got != 0 {
		t.Fatalf("reread before the recheck interval: %v, want the cached 0", got)
	}
	if got := at(300 * time.Millisecond); got != 150*time.Millisecond {
		t.Fatalf("after a write: %v, want 150ms", got)
	}

	writeOffset(t, path, "-90", start.Add(2*time.Second))
	if got := at(600 * time.Millisecond); got != -90*time.Millisecond {
		t.Fatalf("after a second write: %v, want -90ms", got)
	}

	writeOffset(t, path, "garbage", start.Add(3*time.Second))
	if got := at(900 * time.Millisecond); got != -90*time.Millisecond {
		t.Fatalf("a malformed write: %v, want the last good -90ms kept", got)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := at(1200 * time.Millisecond); got != 0 {
		t.Fatalf("file removed: %v, want 0", got)
	}

	writeOffset(t, path, "1234567890123456789012345678901234567890", start.Add(4*time.Second))
	if got := at(1500 * time.Millisecond); got != 0 {
		t.Fatalf("oversized file: %v, want 0", got)
	}
}

func TestNoOffsetFileMeansNoCorrection(t *testing.T) {
	var s MirrorSession
	if s.audioDelay(time.Now()) != 0 || s.videoDelay(time.Now()) != 0 {
		t.Fatal("a session without an offset file shifted a stream")
	}
}

// offsetSession is a session on a fixed media clock with the given offset.
func offsetSession(t *testing.T, anchor time.Time, value string) *MirrorSession {
	t.Helper()
	s := &MirrorSession{
		timestampBias: 100 * time.Millisecond,
		mediaClock:    &mediaClock{anchorLocal: anchor, anchorTimestamp: 1 << 40, timelineID: 7},
		streamDone:    make(chan struct{}),
	}
	if value != "" {
		path := filepath.Join(t.TempDir(), "offset")
		writeOffset(t, path, value, anchor)
		s.avOffset = newAVOffsetSource(path)
	}
	return s
}

func near(a, b uint64) bool {
	if a > b {
		return a-b <= 1
	}
	return b-a <= 1
}

func TestANegativeOffsetShiftsTheVideoTimestampOnly(t *testing.T) {
	anchor := time.Now()
	captured, now := anchor.Add(time.Second), anchor.Add(time.Second+20*time.Millisecond)

	plain := offsetSession(t, anchor, "")
	shifted := offsetSession(t, anchor, "-250")

	plainVideo, _, ok1 := plain.frameTimeAtNow(captured, now)
	shiftedVideo, _, ok2 := shifted.frameTimeAtNow(captured, now)
	if !ok1 || !ok2 {
		t.Fatal("frame time not mapped")
	}
	if !near(shiftedVideo-plainVideo, compactTimestamp(250*time.Millisecond)) {
		t.Fatalf("video moved by %d, want %d (250ms later)", shiftedVideo-plainVideo, compactTimestamp(250*time.Millisecond))
	}
	plainAudio, _ := plain.audioClockAt(captured)
	shiftedAudio, _ := shifted.audioClockAt(captured)
	if plainAudio != shiftedAudio {
		t.Fatalf("the audio clock moved: %d vs %d", shiftedAudio, plainAudio)
	}
}

func TestAPositiveOffsetLeavesTheVideoTimestampAlone(t *testing.T) {
	anchor := time.Now()
	captured, now := anchor.Add(time.Second), anchor.Add(time.Second+20*time.Millisecond)
	plainVideo, _, _ := offsetSession(t, anchor, "").frameTimeAtNow(captured, now)
	shiftedVideo, _, _ := offsetSession(t, anchor, "180").frameTimeAtNow(captured, now)
	if plainVideo != shiftedVideo {
		t.Fatalf("a positive offset moved the video: %d vs %d", shiftedVideo, plainVideo)
	}
}

// ---- video send queue

type sendLog struct {
	mu   sync.Mutex
	sent []int
	at   []time.Time
}

func (l *sendLog) send(id int) func() error {
	return func() error {
		l.mu.Lock()
		l.sent = append(l.sent, id)
		l.at = append(l.at, time.Now())
		l.mu.Unlock()
		return nil
	}
}

func (l *sendLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sent)
}

func TestWithoutAVideoDelayFramesGoOutAtOnce(t *testing.T) {
	s := offsetSession(t, time.Now(), "180") // audio delay only
	var log sendLog
	if err := s.videoSend(log.send(1)); err != nil {
		t.Fatal(err)
	}
	if log.count() != 1 || s.videoLine != nil {
		t.Fatalf("sent %d frames synchronously, queue created=%v; want 1 and no queue", log.count(), s.videoLine != nil)
	}
}

func TestAVideoDelayHoldsFramesBackInOrder(t *testing.T) {
	s := offsetSession(t, time.Now(), "-150")
	defer s.stopVideoDelayLine()
	var log sendLog
	start := time.Now()
	for i := 1; i <= 3; i++ {
		if err := s.videoSend(log.send(i)); err != nil {
			t.Fatal(err)
		}
	}
	if log.count() != 0 {
		t.Fatalf("%d frames went out before their delay", log.count())
	}
	deadline := time.Now().Add(2 * time.Second)
	for log.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.sent) != 3 || log.sent[0] != 1 || log.sent[1] != 2 || log.sent[2] != 3 {
		t.Fatalf("sent %v, want [1 2 3]", log.sent)
	}
	if held := log.at[0].Sub(start); held < 140*time.Millisecond {
		t.Fatalf("first frame held %v, want about 150ms", held)
	}
}

// Dropping the delay while frames still wait must not let a new frame
// overtake them: the decoder needs them in order.
func TestFramesQueuedBeforeTheDelayDropsStillGoFirst(t *testing.T) {
	anchor := time.Now()
	s := offsetSession(t, anchor, "-150")
	defer s.stopVideoDelayLine()
	var log sendLog
	if err := s.videoSend(log.send(1)); err != nil {
		t.Fatal(err)
	}
	s.avOffset = nil // the slider went back to 0
	if err := s.videoSend(log.send(2)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for log.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.sent) != 2 || log.sent[0] != 1 {
		t.Fatalf("sent %v, want [1 2]", log.sent)
	}
}

// ---- audio delay buffer

type fakePCMSource struct {
	mu   sync.Mutex
	next uint32
	spf  uint32
}

func (f *fakePCMSource) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	time.Sleep(8 * time.Millisecond) // one ALAC block of real time
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range dst {
		dst[i] = byte(f.next)
	}
	pos := audioPCMFramePosition{PTS: time.Now(), SourceRTP: f.next, HasSourceRTP: true}
	f.next += f.spf
	return pos, nil
}

func TestAnAudioDelayHoldsBlocksBackAndMovesTheirPositions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newAudioDelayReader(ctx, &fakePCMSource{spf: 352}, func(time.Time) time.Duration { return 120 * time.Millisecond })
	shift := uint32(15) // 120 ms in 352-sample blocks at 44.1 kHz

	buf := make([]byte, 1408)
	for i := uint32(0); i < 5; i++ {
		before := time.Now()
		pos, err := r.ReadPCMFramePosition(buf)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && time.Since(before) < 110*time.Millisecond {
			t.Fatalf("first block came after %v, want it held about 120ms", time.Since(before))
		}
		// Stamped as if captured when released: fresh, so not dropped as stale.
		if age := time.Since(pos.PTS); age > 30*time.Millisecond || age < -30*time.Millisecond {
			t.Fatalf("block %d stamped %v from now, want about now", i, age)
		}
		// The receiver schedules by this position: it must move with the delay.
		if pos.SourceRTP != (i+shift)*352 || buf[0] != byte(i*352) {
			t.Fatalf("block %d: position %d content %d, want position %d content %d",
				i, pos.SourceRTP, buf[0], (i+shift)*352, byte(i*352))
		}
	}
}

// contentOf is what the fake source writes into block k: its position, truncated.
func contentOf(k uint32) byte { return byte(k * 352) }

type settableDelay struct{ ms atomic.Int64 }

func (d *settableDelay) get(time.Time) time.Duration {
	return time.Duration(d.ms.Load()) * time.Millisecond
}

func readBlocks(t *testing.T, r *audioDelayReader, n int) (positions []uint32, contents []byte) {
	t.Helper()
	buf := make([]byte, 1408)
	for i := 0; i < n; i++ {
		pos, err := r.ReadPCMFramePosition(buf)
		if err != nil {
			t.Fatal(err)
		}
		positions = append(positions, pos.SourceRTP)
		silent := true
		for _, b := range buf {
			if b != 0 {
				silent = false
				break
			}
		}
		if silent {
			contents = append(contents, 0)
		} else {
			contents = append(contents, buf[0])
		}
	}
	return positions, contents
}

func continuous(positions []uint32) bool {
	for i := 1; i < len(positions); i++ {
		if positions[i] != positions[i-1]+352 {
			return false
		}
	}
	return true
}

func TestRaisingTheAudioDelayInsertsSilenceAndStaysContinuous(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var delay settableDelay
	// Content byte i*352 truncated to 8 bits; block 0 is all zeros, so start at 1.
	src := &fakePCMSource{spf: 352, next: 352}
	r := newAudioDelayReader(ctx, src, delay.get)

	before, _ := readBlocks(t, r, 3)
	delay.ms.Store(40) // 5 blocks
	after, contents := readBlocks(t, r, 7)

	all := append(before, after...)
	if !continuous(all) {
		t.Fatalf("positions jumped: %v", all)
	}
	for i := 0; i < 5; i++ {
		if contents[i] != 0 {
			t.Fatalf("block %d after raising the delay was not silence: %v", i, contents)
		}
	}
	if contents[5] != contentOf(4) {
		t.Fatalf("audio did not resume where it left off: %v", contents)
	}
}

func TestLoweringTheAudioDelaySkipsAudioAndStaysContinuous(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var delay settableDelay
	delay.ms.Store(40) // 5 blocks
	src := &fakePCMSource{spf: 352, next: 352}
	r := newAudioDelayReader(ctx, src, delay.get)

	before, firstContents := readBlocks(t, r, 3)
	delay.ms.Store(0)
	after, contents := readBlocks(t, r, 2)

	all := append(before, after...)
	if !continuous(all) {
		t.Fatalf("positions jumped: %v", all)
	}
	// Blocks 1..3 went out; 4..8 are skipped (their places were taken); 9 is next.
	if firstContents[2] != contentOf(3) || contents[0] != contentOf(9) {
		t.Fatalf("content before %v after %v; want 5 blocks skipped", firstContents, contents)
	}
}

func TestWithoutAnAudioDelayBlocksPassStraightThrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newAudioDelayReader(ctx, &fakePCMSource{spf: 352}, func(time.Time) time.Duration { return 0 })
	buf := make([]byte, 1408)
	before := time.Now()
	pos, err := r.ReadPCMFramePosition(buf)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(before); took > 60*time.Millisecond {
		t.Fatalf("an undelayed block took %v", took)
	}
	if age := time.Since(pos.PTS); age > 30*time.Millisecond {
		t.Fatalf("an undelayed block was restamped %v old", age)
	}
}

func TestTheAudioBufferIsOnlyAddedWhenAnOffsetFileIsGiven(t *testing.T) {
	src := &fakePCMSource{spf: 352}
	capture := &AudioCapture{pcmFrames: rtpFrameReaderFor(src)}
	var s MirrorSession
	s.delayAudioCapture(context.Background(), capture)
	if _, wrapped := capture.pcmFrames.(*audioDelayReader); wrapped {
		t.Fatal("added the delay buffer without an offset file")
	}
	s.avOffset = newAVOffsetSource(filepath.Join(t.TempDir(), "offset"))
	s.delayAudioCapture(context.Background(), capture)
	if _, wrapped := capture.pcmFrames.(*audioDelayReader); !wrapped {
		t.Fatal("no delay buffer with an offset file")
	}
}

// rtpFrameReaderFor adapts the fake to the capture's reader interface.
type positionedFake struct{ *fakePCMSource }

func (p positionedFake) ReadPCMFrame(dst []byte) (time.Time, error) {
	pos, err := p.ReadPCMFramePosition(dst)
	return pos.PTS, err
}

func rtpFrameReaderFor(f *fakePCMSource) audioPCMFrameReader { return positionedFake{f} }
