package airplay

// Audio/video sync correction (-av-offset-file).
//
// The offset lives in a small file that castr's delay slider writes. Positive
// delays the audio; negative delays the video, so the audio comes sooner.
//
// Shifting timestamps alone is not enough: a Roku TV presents mirrored video
// and plays audio as they arrive, whatever the timestamps say: shifting them
// alone moved nothing on one. So the delayed stream is really held back before it is
// sent, and its timestamps move by the same amount, which keeps it consistent
// for a receiver that does honour them:
//
//   - video: encoded frames wait in a queue and go out late, in order, while
//     the encoder keeps being read; their presentation time is shifted too;
//   - audio: captured blocks wait in a buffer and are handed on late with
//     their sample positions (RTP) moved later too, see audioDelayReader.
//
// A change applies within a quarter of a second.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// AVOffsetLimit bounds the correction either way.
	AVOffsetLimit    = 1000 * time.Millisecond
	avOffsetRecheck  = 250 * time.Millisecond
	avOffsetMaxBytes = 32

	// Room for a full second of either stream: 30 fps of video plus codec
	// frames, and ~125 ALAC blocks of audio.
	videoDelayQueue = 256
	audioDelayQueue = 512
	// A waiting block rechecks the delay this often, so lowering the slider
	// releases held audio promptly instead of at the old deadline.
	audioDelayRecheck = 20 * time.Millisecond
)

// avOffsetSource follows the offset file. A missing or unreadable file means
// no correction; a malformed one keeps the last good value.
type avOffsetSource struct {
	path string

	mu      sync.Mutex
	checked time.Time
	modTime time.Time
	size    int64
	value   time.Duration
}

func newAVOffsetSource(path string) *avOffsetSource {
	if path == "" {
		return nil
	}
	return &avOffsetSource{path: path}
}

// at returns the offset, rereading the file at most every avOffsetRecheck.
func (o *avOffsetSource) at(now time.Time) time.Duration {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.checked.IsZero() && now.Sub(o.checked) >= 0 && now.Sub(o.checked) < avOffsetRecheck {
		return o.value
	}
	o.checked = now

	info, err := os.Stat(o.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > avOffsetMaxBytes {
		o.set(0)
		o.modTime, o.size = time.Time{}, 0
		return o.value
	}
	if info.ModTime().Equal(o.modTime) && info.Size() == o.size {
		return o.value
	}
	data, err := os.ReadFile(o.path)
	if err != nil {
		return o.value
	}
	o.modTime, o.size = info.ModTime(), info.Size()
	if value, ok := parseAVOffset(data); ok {
		o.set(value)
	}
	return o.value
}

func (o *avOffsetSource) set(value time.Duration) {
	if value != o.value {
		log.Printf("audio/video offset: %+d ms", value.Milliseconds())
	}
	o.value = value
}

// parseAVOffset reads whole milliseconds, signed, and clamps them.
func parseAVOffset(data []byte) (time.Duration, bool) {
	ms, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	value := time.Duration(ms) * time.Millisecond
	if value > AVOffsetLimit {
		value = AVOffsetLimit
	}
	if value < -AVOffsetLimit {
		value = -AVOffsetLimit
	}
	return value, true
}

// audioDelay is how much later than captured the audio is sent and announced.
func (s *MirrorSession) audioDelay(now time.Time) time.Duration {
	if value := s.avOffset.at(now); value > 0 {
		return value
	}
	return 0
}

// videoDelay is how much later than captured the video is sent and presented.
func (s *MirrorSession) videoDelay(now time.Time) time.Duration {
	if value := s.avOffset.at(now); value < 0 {
		return -value
	}
	return 0
}

// ---------------------------------------------------------------- video

type delayedVideoSend struct {
	due  time.Time
	send func() error
}

// videoDelayLine sends queued video in order, each item at its due time.
type videoDelayLine struct {
	queue   chan delayedVideoSend
	stop    chan struct{}
	done    chan struct{}
	pending atomic.Int64
	sendMu  sync.Mutex // one send at a time: sendFrame advances nonces and sequence numbers
	errMu   sync.Mutex
	err     error
	once    sync.Once
}

func newVideoDelayLine(fail func(error)) *videoDelayLine {
	line := &videoDelayLine{
		queue: make(chan delayedVideoSend, videoDelayQueue),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go line.run(fail)
	return line
}

func (line *videoDelayLine) run(fail func(error)) {
	defer close(line.done)
	for {
		var item delayedVideoSend
		select {
		case <-line.stop:
			return
		case item = <-line.queue:
		}
		if wait := time.Until(item.due); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-line.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		line.sendMu.Lock()
		err := item.send()
		line.sendMu.Unlock()
		line.pending.Add(-1)
		if err != nil {
			line.errMu.Lock()
			if line.err == nil {
				line.err = err
			}
			line.errMu.Unlock()
			if fail != nil {
				fail(fmt.Errorf("delayed video send: %w", err))
			}
			return
		}
	}
}

func (line *videoDelayLine) failure() error {
	line.errMu.Lock()
	defer line.errMu.Unlock()
	return line.err
}

func (line *videoDelayLine) close() {
	line.once.Do(func() { close(line.stop) })
	<-line.done
}

// videoSend sends now when no video delay is set and nothing is queued, which
// is upstream's path unchanged; otherwise it queues the send for later. Called
// from the one goroutine that reads the encoder.
func (s *MirrorSession) videoSend(send func() error) error {
	now := time.Now()
	delay := s.videoDelay(now)
	line := s.videoLine
	if delay <= 0 && (line == nil || line.pending.Load() == 0) {
		if line != nil {
			line.sendMu.Lock()
			defer line.sendMu.Unlock()
		}
		return send()
	}
	if line == nil {
		line = newVideoDelayLine(s.failStream)
		s.videoLine = line
	}
	if err := line.failure(); err != nil {
		return err
	}
	line.pending.Add(1)
	select {
	case line.queue <- delayedVideoSend{due: now.Add(delay), send: send}:
		return nil
	case <-line.stop:
		line.pending.Add(-1)
		return errors.New("video delay line stopped")
	}
}

func (s *MirrorSession) stopVideoDelayLine() {
	if s.videoLine != nil {
		s.videoLine.close()
	}
}

// ---------------------------------------------------------------- audio

type delayedPCMFrame struct {
	pcm []byte
	pos audioPCMFramePosition
	at  time.Time
	err error
}

// audioDelayReader holds captured audio back by the audio delay and moves its
// sample positions (which become RTP timestamps) later by the same amount.
//
// A Roku schedules audio by RTP timestamp against a clock it fixes when the
// cast starts, with ~100 ms of headroom: audio that is only held back arrives
// after its slot and is thrown away (choppy past about +80 ms), and later
// TimeAnnounces are ignored. So the delay is carried in the
// sample positions themselves, in whole blocks, and the positions stay
// continuous: raising the delay hands on that much silence first, lowering it
// skips that much audio. The receiver sees one unbroken stream either way.
type audioDelayReader struct {
	ctx    context.Context
	src    audioPCMFramePositionReader
	delay  func(time.Time) time.Duration
	frames chan delayedPCMFrame
	start  sync.Once

	// What has been handed on so far, to keep positions continuous.
	emitted bool
	nextSRC uint32    // sample position the next block must carry
	nextPTS time.Time // and its stamp
	held    *delayedPCMFrame
	silence int // blocks of silence to hand on before held
}

func newAudioDelayReader(ctx context.Context, src audioPCMFramePositionReader, delay func(time.Time) time.Duration) *audioDelayReader {
	return &audioDelayReader{ctx: ctx, src: src, delay: delay, frames: make(chan delayedPCMFrame, audioDelayQueue)}
}

func (r *audioDelayReader) pump(size int) {
	for {
		pcm := make([]byte, size)
		pos, err := r.src.ReadPCMFramePosition(pcm)
		select {
		case r.frames <- delayedPCMFrame{pcm: pcm, pos: pos, at: time.Now(), err: err}:
		case <-r.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// waitUntil sleeps until due, rechecking due() so a lowered delay releases
// held audio promptly.
func (r *audioDelayReader) waitUntil(due func() time.Time) error {
	for {
		wait := time.Until(due())
		if wait <= 0 {
			return nil
		}
		if wait > audioDelayRecheck {
			wait = audioDelayRecheck
		}
		timer := time.NewTimer(wait)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return io.EOF
		case <-timer.C:
		}
	}
}

// shiftBlocks is the current delay in whole blocks of frameSamples.
func (r *audioDelayReader) shiftBlocks(blockDuration time.Duration) uint32 {
	d := r.delay(time.Now())
	if d <= 0 || blockDuration <= 0 {
		return 0
	}
	return uint32((d + blockDuration/2) / blockDuration)
}

// ReadPCMFramePosition hands on the next block once its delay has passed.
func (r *audioDelayReader) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	r.start.Do(func() { go r.pump(len(dst)) })
	frameSamples := uint32(len(dst) / (audioChannels * 2))
	blockDuration := audioSamplesDuration(uint64(frameSamples))

	for {
		if r.silence > 0 {
			due := r.nextPTS
			if err := r.waitUntil(func() time.Time { return due }); err != nil {
				return audioPCMFramePosition{}, err
			}
			clear(dst)
			pos := audioPCMFramePosition{PTS: r.nextPTS, SourceRTP: r.nextSRC, HasSourceRTP: true}
			r.nextSRC += frameSamples
			r.nextPTS = r.nextPTS.Add(blockDuration)
			r.silence--
			return pos, nil
		}

		var item delayedPCMFrame
		if r.held != nil {
			item, r.held = *r.held, nil
		} else {
			select {
			case item = <-r.frames:
			case <-r.ctx.Done():
				return audioPCMFramePosition{}, io.EOF
			}
			if item.err != nil {
				return audioPCMFramePosition{}, item.err
			}
		}
		base := item.pos.PTS
		if base.IsZero() {
			base = item.at
		}
		if err := r.waitUntil(func() time.Time {
			return base.Add(time.Duration(r.shiftBlocks(blockDuration)) * blockDuration)
		}); err != nil {
			return audioPCMFramePosition{}, err
		}

		shift := r.shiftBlocks(blockDuration)
		pos := item.pos
		pos.PTS = base.Add(time.Duration(shift) * blockDuration)
		if !pos.HasSourceRTP {
			// No sample positions to move: held back and restamped only.
			copy(dst, item.pcm)
			return pos, nil
		}
		pos.SourceRTP += shift * frameSamples
		if r.emitted {
			gap := int32(pos.SourceRTP - r.nextSRC)
			if gap < 0 {
				// The delay went down: this audio's place was already sent.
				continue
			}
			if gap >= int32(frameSamples) {
				// The delay went up: silence first, then this block.
				r.silence = int(uint32(gap) / frameSamples)
				r.held = &item
				continue
			}
		}
		copy(dst, item.pcm)
		r.emitted = true
		r.nextSRC = pos.SourceRTP + frameSamples
		r.nextPTS = pos.PTS.Add(blockDuration)
		return pos, nil
	}
}

func (r *audioDelayReader) ReadPCMFrame(dst []byte) (time.Time, error) {
	pos, err := r.ReadPCMFramePosition(dst)
	return pos.PTS, err
}

// delayAudioCapture puts the delay buffer in front of a timestamped capture.
// The unframed fallback has no capture times to work from and is left alone.
func (s *MirrorSession) delayAudioCapture(ctx context.Context, capture *AudioCapture) {
	if s.avOffset == nil || capture == nil || capture.pcmFrames == nil {
		return
	}
	positioned, ok := capture.pcmFrames.(audioPCMFramePositionReader)
	if !ok {
		return
	}
	capture.pcmFrames = newAudioDelayReader(ctx, positioned, s.audioDelay)
	dbg("[AUDIO] audio delay buffer in place")
}
