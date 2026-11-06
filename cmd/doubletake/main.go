package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"doubletake/internal/airplay"
	"doubletake/internal/daemon"
)

func parseXID(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 0, 64) // accepts decimal or 0xhex
}

// parsePortRange parses a "min-max" string into inclusive port bounds.
// An empty string returns (0, 0, nil) meaning "let the OS pick".
func parsePortRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected MIN-MAX, got %q", s)
	}
	lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("min: %w", err)
	}
	hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("max: %w", err)
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("range %d-%d out of bounds (1-65535, min<=max)", lo, hi)
	}
	if hi-lo+1 < 3 {
		return 0, 0, fmt.Errorf("range %d-%d too small; need 3 consecutive UDP ports", lo, hi)
	}
	return lo, hi, nil
}

func main() {
	target := flag.String("target", "", "Apple TV IP address or hostname (skip discovery)")
	port := flag.Int("port", 7000, "AirPlay port")
	code := flag.String("code", "", "Pairing PIN shown on the receiver, or the password set on it when \"Require Password\" is enabled; prefer $DOUBLETAKE_CODE so it stays out of shell history and ps output")
	credFile := flag.String("creds", airplay.DefaultCredentialsPath(), "Path to saved pairing credentials")
	credBackend := flag.String("cred-backend", "file", "Credential storage backend: file or keyring (system keyring via Secret Service)")
	forcePair := flag.Bool("pair", false, "Force new pairing even if credentials exist")
	expectedDeviceID := flag.String("device-id", "", "Device ID of the receiver meant, e.g. from discovery. Its saved pairing applies even if the device at -target names itself differently, and such a device is refused")
	fps := flag.Int("fps", 30, "Frames per second")
	bitrate := flag.Int("bitrate", 0, "Video bitrate in kbps (0 = auto, default tunes for resolution/FPS)")
	targetLatencyMs := flag.Int("target-latency-ms", 0, "Joint audio/video playout latency override in milliseconds (0 = automatic connection profile)")
	hwaccel := flag.String("hwaccel", "auto", "Encoder: auto, nvenc, vaapi, openh264, none (x264/x265)")
	videoCodec := flag.String("video-codec", "auto", "Screen codec: auto, h264, or hevc (auto uses H.264 for receiver compatibility)")
	testMode := flag.Bool("test", false, "Use synthetic video (videotestsrc) instead of screen capture for debugging")
	noEncrypt := flag.Bool("no-encrypt", false, "Send video frames unencrypted (debugging, or a receiver with neither an encrypted control channel nor FairPlay, which has no protected way to receive the video key)")
	directKey := flag.Bool("direct-key", false, "Use shk/shiv directly without SHA-512 derivation")
	noAudio := flag.Bool("no-audio", false, "Disable audio streaming")
	portRange := flag.String("port-range", "", "Local UDP port range for receiver timing/audio (e.g. \"60000-60010\"); empty = OS ephemeral. Needs at least 3 ports.")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	daemonize := flag.Bool("daemonize", false, "Run as background daemon with Unix socket control interface")
	socketPath := flag.String("socket", daemon.DefaultSocketPath(), "Unix socket path for daemon control interface")
	x11WindowID := flag.String("x11-window-id", "", "X11 window id to capture, decimal or 0xhex")
	x11WindowName := flag.String("x11-window-name", "", "X11 window name to capture; prefer -x11-window-id")
	audioSource := flag.String("audio-source", "", "PulseAudio/PipeWire source to capture audio from (e.g. a null sink monitor); empty = default output monitor")
	noCursor := flag.Bool("no-cursor", false, "Don't show the mouse cursor in the captured video")
	flag.Parse()
	if err := airplay.ValidateHWAccel(*hwaccel); err != nil {
		log.Fatalf("invalid -hwaccel: %v", err)
	}
	if err := airplay.ValidateVideoCodec(*videoCodec); err != nil {
		log.Fatalf("invalid -video-codec: %v", err)
	}
	portMin, portMax, err := parsePortRange(*portRange)
	if err != nil {
		log.Fatalf("invalid -port-range: %v", err)
	}
	// The environment wins over the flag: it keeps the code out of shell history
	// and out of `ps`, where a command line is readable by other users.
	credential := *code
	if env := os.Getenv("DOUBLETAKE_CODE"); env != "" {
		credential = env
	}

	airplay.SetTargetLatency(time.Duration(*targetLatencyMs) * time.Millisecond)

	airplay.SetDebugMode(*debug)

	if *daemonize {
		runDaemon(daemon.Config{
			SocketPath:  *socketPath,
			CredFile:    *credFile,
			CredBackend: *credBackend,
			FPS:         *fps,
			Bitrate:     *bitrate,
			PortMin:     portMin,
			PortMax:     portMax,
			HWAccel:     *hwaccel,
			VideoCodec:  airplay.VideoCodec(*videoCodec),
			Debug:       *debug,
			TestMode:    *testMode,
			NoEncrypt:   *noEncrypt,
			DirectKey:   *directKey,
			NoAudio:     *noAudio,
			ShowCursor:  !*noCursor,
			Code:        credential,
		})
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	xid, err := parseXID(*x11WindowID)
	if err != nil {
		log.Fatalf("invalid -x11-window-id: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
		// Give goroutines a moment to clean up, then force exit
		go func() {
			time.Sleep(3 * time.Second)
			log.Println("forced exit (timeout)")
			os.Exit(1)
		}()
		// Also force exit on second signal
		<-sigCh
		log.Println("forced exit")
		os.Exit(1)
	}()

	var addr string
	var advertisement *airplay.AirPlayDevice
	if *target != "" {
		addr = *target
	} else {
		device, err := selectDevice(ctx)
		if err != nil {
			log.Fatalf("discovery failed: %v", err)
		}
		addr = device.IP
		*port = device.Port
		advertisement = device
		fmt.Printf("selected: %s (%s:%d)\n", device.Name, device.IP, device.Port)
	}

	var client *airplay.AirPlayClient
	newClient := func() *airplay.AirPlayClient {
		if advertisement != nil {
			device := *advertisement
			device.IP = addr
			device.Port = *port
			return airplay.NewAirPlayClientForDevice(device)
		}
		return airplay.NewAirPlayClient(addr, *port)
	}

	credStore, err := newCredentialStore(*credBackend, *credFile)
	if err != nil {
		log.Fatalf("failed to load credentials: %v", err)
	}
	// The receiver meant: as given, as discovery advertised it when it was
	// picked, or the one last paired at -target. Without any, the device at
	// -target is taken at its word.
	expectedID := *expectedDeviceID
	if expectedID == "" && advertisement != nil {
		expectedID = advertisement.DeviceID
	}
	var binding airplay.AddressBinding
	if expectedID == "" && *target != "" && !*forcePair {
		// With -pair the user is pairing deliberately with whatever is at the
		// address now, so the receiver paired there before does not refuse
		// it; the new pairing takes the address over.
		binding, err = credStore.BindingAt(addr)
		if err != nil {
			log.Fatalf("%v; refusing to cast", err)
		}
		// After a tie the receiver meant is whichever tied one answers.
		expectedID = binding.DeviceID
	}
	boundByAddress := binding.Bound()
	// A receiver this machine has paired with must prove itself before the
	// code goes anywhere: the client answers any 401 with an MD5 Digest of
	// it, crackable offline when the code is short, and a device at the
	// address can challenge before pair-verify. So the password is installed
	// only once the receiver has proven itself -- also for a pairing saved
	// before receiver identities, which proves itself by pairing again.
	holdPassword := boundByAddress
	if expectedID != "" {
		expected, err := credStore.LookupReceiver(expectedID, expectedID)
		if err != nil {
			log.Fatalf("%v; refusing to cast", err)
		}
		holdPassword = expected.HasPairingCredentials()
	}
	// proven: the receiver has shown it is the one paired with, by
	// pair-verify against its saved identity or by pairing with a code.
	proven := false
	installPassword := func() {
		if !holdPassword {
			client.SetPassword(credential)
		}
	}

	client = newClient()
	installPassword()
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	info, err := client.GetInfo()
	if err != nil {
		log.Fatalf("get info failed: %v", err)
	}
	log.Printf("connected to: %s (model: %s, initialVolume: %.1f)", info.Name, info.Model, info.InitialVolume)
	if credential == "" && info.RequiresPassword() {
		credential = readCredential(bufio.NewReader(os.Stdin), "Enter the receiver's configured password: ")
		if credential == "" {
			log.Fatal("password cannot be empty")
		}
		installPassword()
	}

	// Pairing flow:
	// 1. If --pair is forced, do full pair-setup and save credentials.
	// 2. If saved credentials exist, load them and do pair-verify only.
	// 3. Pair directly when a legacy receiver requires its configured password,
	//    or when the receiver advertises one-time PIN pairing.
	// 4. Otherwise, try transient pairing and use a fresh connection for fallback.
	//
	// -code alone does not force pairing. A receiver with "Require Password"
	// needs the code on every session, so treating its presence as "pair again"
	// would re-pair on every run and throw away working credentials. When a
	// pairing PIN is what is actually wanted, -pair asks for one.
	needFullPair := *forcePair

	// Looked up even for -pair: a receiver this machine has paired with is
	// paired with again only with a code, never transiently.
	if expectedID == "" && !boundByAddress {
		log.Printf("warning: no -device-id; a device at %s naming itself as a new receiver would be paired with from scratch", addr)
	}
	if expectedID == "" && boundByAddress {
		if expectedID, err = binding.ReceiverMeant(info.DeviceID); err != nil {
			log.Fatalf("%v; refusing to cast", err)
		}
	}
	savedCreds, err := credStore.LookupReceiver(expectedID, info.DeviceID)
	if err != nil {
		if boundByAddress && errors.Is(err, airplay.ErrReceiverNotAuthenticated) {
			log.Fatalf("%v; refusing to cast. %s is the receiver this machine paired with at %s; "+
				"if a different receiver now has that address, pair with it explicitly: run again "+
				"with -pair and enter the code it shows.", err, expectedID, addr)
		}
		log.Fatalf("%v; refusing to cast", err)
	}
	pairedWithCode := savedCreds.HasPairingCredentials() && !savedCreds.UsesRawPairing()
	if savedCreds.HasPairingCredentials() && !holdPassword {
		// Found only by the ID the device reported; it still proves itself
		// before the password is used again.
		holdPassword = true
		client.SetPassword("")
	}

	reconnect := func() {
		_ = client.Close()
		client = newClient()
		installPassword()
		if err := client.Connect(ctx); err != nil {
			log.Fatalf("reconnect failed: %v", err)
		}
		var err error
		previousID := info.DeviceID
		info, err = client.GetInfo()
		if err != nil {
			log.Fatalf("get info after reconnect failed: %v", err)
		}
		// Whatever is paired with next is saved under this ID, so the device
		// may not change it between connections.
		if !strings.EqualFold(info.DeviceID, previousID) {
			log.Fatalf("the receiver named itself %q, then %q after reconnecting; refusing to cast",
				previousID, info.DeviceID)
		}
	}

	var pairWithCredential func(value string, expectPIN bool, kind airplay.PairingCode)
	savePairingCredentials := func(kind airplay.PairingCode) {
		// Only a pairing that proved the receiver's identity is worth saving:
		// without that identity a later pair-verify has nothing to check the
		// receiver against.
		receiver := client.ReceiverIdentity()
		if client.PairKeys == nil || receiver == nil {
			return
		}
		if err := credStore.SavePairing(info.DeviceID, client.PairingID,
			client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private,
			client.PairingProtocol(), receiver, airplay.PairingOrigin{Code: kind, Address: addr}); err != nil {
			log.Printf("warning: failed to save credentials: %v", err)
		} else {
			log.Printf("credentials saved (%s)", *credBackend)
		}
	}
	pairFresh := func() {
		if passwordRequiresPairing(info) {
			pairWithCredential("", false, airplay.PairingCodePassword)
		} else if info.RequiredPairingCredential() == airplay.PairingCredentialPIN {
			pairWithCredential("", true, airplay.PairingCodePIN)
		} else if err := client.Pair(ctx, ""); err != nil {
			if info.RequiresPassword() {
				log.Fatalf("transient pairing failed for password-protected receiver: %v", err)
			}
			log.Printf("transient pairing failed: %v, requesting pairing credentials", err)
			reconnect()
			// Nothing advertised which code this receiver takes; the prompt
			// decides, by whether it showed a PIN.
			pairWithCredential("", false, airplay.PairingCodeNone)
		}
	}
	// pairWithCredential pairs with a code of the given kind; with no kind,
	// it is a PIN if the receiver accepted the request to show one.
	pairWithCredential = func(value string, expectPIN bool, kind airplay.PairingCode) {
		if value == "" {
			var pinShown bool
			value, pinShown = credentialOrPrompt(credential, client, expectPIN)
			if kind == airplay.PairingCodeNone {
				kind = airplay.PairingCodePassword
				if pinShown {
					kind = airplay.PairingCodePIN
				}
			}
		}
		if kind == airplay.PairingCodeNone {
			kind = airplay.PairingCodePassword
		}
		// AirPlay uses the same user-entered value for pair-setup and, on
		// password-protected receivers, the later HTTP Digest challenge.
		// Keep it for reconnects as well as the current connection.
		credential = value
		if err := client.Pair(ctx, value); err != nil {
			log.Fatalf("pairing failed: %v", err)
		}
		savePairingCredentials(kind)
	}
	// pairAgainWithCode pairs again with a receiver this machine has paired
	// with before, with the kind of code its saved pairing was made with;
	// airplay.PairAgainWithCode says why /info is not asked.
	pairAgainWithCode := func(explicit bool) {
		reader := bufio.NewReader(os.Stdin)
		kind, err := client.PairAgainWithCode(ctx, savedCreds, explicit, credential, airplay.CodePrompts{
			PIN: func() (string, error) {
				// A PIN is shown afresh each time, so a preset -code cannot be it.
				code := readCredential(reader, pairingCredentialPrompt(true, nil))
				if code == "" {
					return "", errors.New("the PIN cannot be empty")
				}
				return code, nil
			},
			Password: func() (string, error) {
				code := readCredential(reader, "Enter the receiver's pairing password: ")
				if code == "" {
					return "", errors.New("the pairing password cannot be empty")
				}
				// Also the receiver's Digest password; keep it for reconnects.
				credential = code
				return code, nil
			},
		})
		if errors.Is(err, airplay.ErrPasswordPairingNotRepeated) {
			log.Fatalf("%v; refusing to pair with %q again automatically. If it is the receiver you "+
				"paired with, run again with -pair to pair with it again.", err, info.Name)
		}
		if err != nil {
			log.Fatalf("pairing failed: %v", err)
		}
		proven = true
		savePairingCredentials(kind)
	}
	// pairAgainRaw pairs again with a receiver whose saved pairing is a raw
	// one made before receiver identities. Raw receivers keep no pairing
	// across connections, so nothing can be pinned: each connection is
	// trusted as at a first contact, which saves nothing, and the code is
	// then released for the receiver's Digest as there. What a raw entry
	// still guarantees (airplay.PairAgainRaw) is that it never leads to
	// pairing with a code, a Digest before the raw pairing, or a transient
	// fallback.
	pairedRaw := false
	pairAgainRaw := func() {
		if err := client.PairAgainRaw(ctx); err != nil {
			log.Fatalf("%v; refusing to cast", err)
		}
		pairedRaw = true
	}
	if needFullPair && pairedWithCode {
		pairAgainWithCode(true)
	} else if needFullPair {
		if forcePairUsesTransient(info) {
			// A modern receiver's fixed playback password belongs only to HTTP
			// Digest. Passing it to full SRP pair-setup is rejected as a bad PIN,
			// even when -pair was requested. Keep the one entered value for Digest
			// and establish this session with transient HAP pairing.
			if err := client.Pair(ctx, ""); err != nil {
				log.Fatalf("transient pairing failed for password-protected receiver: %v", err)
			}
		} else {
			// Full pair-setup with a supplied PIN/password, or request an onscreen PIN.
			kind := airplay.PairingCodePassword
			if !info.RequiresPassword() {
				kind = airplay.PairingCodePIN
			}
			pairWithCredential(credential, !info.RequiresPassword(), kind)
		}
	} else if savedCreds.HasPairingCredentials() {
		// Once this machine has paired with a receiver, nothing falls back to
		// transient pairing for it; airplay.AfterSavedPairing says why.
		log.Printf("using saved credentials (%s)", *credBackend)
		var verifyErr error
		step := airplay.AfterSavedPairing(savedCreds, func() error {
			verifyErr = restoreSavedPairing(client, savedCreds)
			if verifyErr == nil {
				verifyErr = client.PairVerify(ctx)
			}
			return verifyErr
		})
		if step == airplay.SavedPairingRefuse {
			if errors.Is(verifyErr, airplay.ErrReceiverNotAuthenticated) {
				log.Fatalf("%v; refusing to cast. The device answering as %q is not the receiver "+
					"this machine paired with, or will not prove it. If you reset or replaced that "+
					"receiver, run again with -pair and enter the code it shows; a receiver that "+
					"shows no code is not the one you paired with.", verifyErr, info.Name)
			}
			log.Fatalf("pair-verify with saved creds failed: %v; refusing to replace the saved "+
				"pairing with an unauthenticated one. If you reset or replaced that receiver, "+
				"remove its entry from %s and connect again.", verifyErr, *credFile)
		}
		if step == airplay.SavedPairingVerified {
			proven = true
			if *target != "" {
				// Proven at this address: a pairing saved before addresses
				// were recorded is bound to it from now on.
				if err := credStore.BindAddress(addr, info.DeviceID, expectedID); err != nil {
					log.Printf("warning: failed to record the receiver's address: %v", err)
				}
			}
		} else {
			if verifyErr != nil {
				log.Printf("pair-verify with saved creds failed: %v", verifyErr)
				reconnect()
			} else {
				log.Printf("saved credentials predate receiver authentication; pairing again")
			}
			if step == airplay.SavedPairingPairAsNew {
				pairAgainRaw()
			} else {
				pairAgainWithCode(false)
			}
		}
	} else {
		pairFresh()
	}
	// Installed once the receiver has proven itself, when none was held for
	// it, when -pair asked to pair with whatever is at the address, or after
	// a raw receiver was paired with again as at a first contact.
	if proven || !holdPassword || needFullPair || pairedRaw {
		holdPassword = false
		installPassword()
	}
	log.Println("pairing complete")

	// FairPlay setup — establishes fp-setup state and ekey/eiv used for the
	// final encrypted mirror stream. Pair-verify and FairPlay are both needed
	// for compatibility with the normal modern flow.
	if client.FpEkey == nil {
		if err := client.FairPlaySetup(ctx); err != nil {
			if !errors.Is(err, airplay.ErrFairPlayUnsupported) {
				log.Fatalf("FairPlay setup failed: %v", err)
			}
			log.Printf("FairPlay SAP unsupported (%v); continuing with pair-verify DataStream setup", err)
		} else {
			log.Println("FairPlay setup complete")
		}
	}

	streamCfg := airplay.StreamConfig{
		FPS:        *fps,
		Bitrate:    *bitrate,
		VideoCodec: airplay.VideoCodec(*videoCodec),
		NoEncrypt:  *noEncrypt,
		DirectKey:  *directKey,
		NoAudio:    *noAudio,
		PortMin:    portMin,
		PortMax:    portMax,
	}
	// Complete the potentially interactive Wayland portal request before SETUP,
	// but delay encoder startup until control SETUP returns session-time display
	// information. Some current receivers omit displays before that session
	// exists; committing the pipeline earlier silently selects the 720p fallback.
	captureCfg := airplay.CaptureConfig{
		FPS:           *fps,
		Bitrate:       *bitrate,
		HWAccel:       *hwaccel,
		VideoCodec:    airplay.VideoCodec(*videoCodec),
		X11WindowID:   xid,
		X11WindowName: *x11WindowName,
		ShowCursor:    !*noCursor,
	}
	if *testMode {
		if *noAudio {
			log.Println("using synthetic video (videotestsrc) for debugging")
		} else {
			log.Println("using synthetic video (videotestsrc) and audio test tone for debugging")
		}
	}
	prepareCapture := func(cfg airplay.CaptureConfig) (*airplay.CapturePreparation, error) {
		if *testMode {
			return airplay.PrepareTestCapture(ctx, cfg)
		}
		restoreToken := ""
		if creds := credStore.Lookup(info.DeviceID); creds != nil {
			restoreToken = creds.RestoreToken
		}
		cfg.RestoreToken = restoreToken
		cfg.SaveRestoreToken = func(token string) error {
			return credStore.SaveRestoreToken(info.DeviceID, token)
		}
		return airplay.PrepareCapture(ctx, cfg)
	}
	capturePreparation, err := prepareCapture(captureCfg)
	if err != nil {
		log.Fatalf("prepare screen capture: %v", err)
	}
	streamCfg.AutomaticHEVCAvailable = capturePreparation.AutomaticHEVCAvailable()
	streamCfg.MeasuredVideoLatency = capturePreparation.MeasuredVideoLatency()

	var capture *airplay.ScreenCapture
	var broadcast *airplay.BroadcastCapture
	var broadcastDone chan error
	startedWidth, startedHeight := -1, -1
	startedCodec := airplay.VideoCodec("")
	var liveVideoLead time.Duration
	prepareH264Fallback := func(cause error) error {
		fallbackCfg := captureCfg
		fallbackCfg.VideoCodec = airplay.VideoCodecH264
		replacement, fallbackErr := prepareCapture(fallbackCfg)
		if fallbackErr != nil {
			return fmt.Errorf("%v; prepare H.264 fallback: %w", cause, fallbackErr)
		}
		capturePreparation.Close()
		capturePreparation = replacement
		liveVideoLead = 0
		return fmt.Errorf("%w: %v", airplay.ErrAutomaticVideoCodecUnavailable, cause)
	}
	prepareVideo := func(width, height int, codec airplay.VideoCodec) (airplay.VideoPreparationResult, error) {
		if capture != nil {
			if codec == startedCodec {
				if width != startedWidth || height != startedHeight {
					log.Printf("receiver updated the %s canvas to %dx%d after capture started; keeping %dx%d for this session", codec, width, height, startedWidth, startedHeight)
				}
				return airplay.VideoPreparationResult{MinimumVideoLead: liveVideoLead}, nil
			}
			return airplay.VideoPreparationResult{}, fmt.Errorf("receiver changed video from %s %dx%d to %s %dx%d during setup", startedCodec, startedWidth, startedHeight, codec, width, height)
		}
		startedCapture, startErr := capturePreparation.StartWithCodec(width, height, codec)
		if startErr != nil {
			if captureCfg.VideoCodec == airplay.VideoCodecAuto && codec == airplay.VideoCodecHEVC {
				return airplay.VideoPreparationResult{}, prepareH264Fallback(startErr)
			}
			return airplay.VideoPreparationResult{}, startErr
		}
		if codec == airplay.VideoCodecHEVC && !airplay.HasExplicitTargetLatency() {
			liveVideoLead, startErr = airplay.MeasureVideoCaptureLatency(ctx, startedCapture, *fps)
			if startErr != nil {
				startedCapture.Stop()
				measurementErr := fmt.Errorf("measure production HEVC timing: %w", startErr)
				if captureCfg.VideoCodec == airplay.VideoCodecAuto {
					return airplay.VideoPreparationResult{}, prepareH264Fallback(measurementErr)
				}
				return airplay.VideoPreparationResult{}, measurementErr
			}
			log.Printf("[CAPTURE] production HEVC timing requires at least %v video lead", liveVideoLead)
		}
		activeBroadcast := airplay.NewBroadcastCaptureWithFrameRate(startedCapture, *fps)
		done := make(chan error, 1)
		capture = startedCapture
		broadcast = activeBroadcast
		broadcastDone = done
		startedWidth, startedHeight = width, height
		startedCodec = codec
		go func(active *airplay.BroadcastCapture, result chan<- error) {
			result <- active.Run()
		}(activeBroadcast, done)
		log.Printf("screen capture started at %dx%d using %s", width, height, codec)
		return airplay.VideoPreparationResult{MinimumVideoLead: liveVideoLead}, nil
	}
	defer func() {
		capturePreparation.Close()
		if capture != nil {
			capture.Stop()
			<-broadcastDone
		}
	}()

	session, err := client.SetupMirrorWithCalibratedVideoPreparation(ctx, streamCfg, prepareVideo)
	if errors.Is(err, airplay.ErrCredentialsRequired) {
		// Some legacy receivers do not advertise their configured password in
		// /info. They reveal it only by challenging the first media SETUP. Keep
		// the completed pairing/FairPlay state and running capture, configure the
		// cached Digest challenge, and retry this setup exactly once.
		credential = readCredential(bufio.NewReader(os.Stdin), "Enter the code shown on the receiver, or its configured password: ")
		if credential == "" {
			log.Fatal("receiver code/password cannot be empty")
		}
		client.SetPassword(credential)
		if startedCodec != "" {
			// A late Digest challenge may expose richer authenticated display
			// metadata on the retry. The running encoder is single-use, so pin
			// the already safe concrete codec for the remainder of this session.
			streamCfg.VideoCodec = startedCodec
		}
		session, err = client.SetupMirrorWithCalibratedVideoPreparation(ctx, streamCfg, prepareVideo)
	}
	if err != nil {
		log.Fatalf("mirror setup failed: %v", err)
	}
	if capture == nil || broadcast == nil {
		log.Fatal("mirror setup completed without preparing video capture")
	}
	defer session.Close()
	log.Printf("mirror session ready (data port: %d)", session.DataPort)

	go func() {
		<-ctx.Done()
		capture.Stop()
		session.Close()
	}()

	// Start audio capture and streaming unless disabled.
	if !*noAudio && session.HasAudio() {
		audioCapture, err := airplay.StartAudioCapture(ctx, *testMode, session.AudioCodec(), airplay.AudioCaptureOptions{Source: *audioSource})
		if err != nil {
			log.Printf("warning: audio capture failed: %v (continuing without audio)", err)
		} else {
			defer audioCapture.Stop()
			go func() {
				if err := session.StreamAudio(ctx, audioCapture, session.AudioStream()); err != nil && ctx.Err() == nil {
					log.Printf("audio streaming error: %v", err)
				}
			}()
			log.Println("audio capture started")
		}
	} else if !*noAudio {
		log.Println("audio disabled (receiver did not provide audio ports)")
	}

	// Keep the capture pipeline draining until the receiver is ready to consume
	// video. Holding its first access unit during setup can exhaust the portal
	// buffer pool. StreamFrames waits for the next parameter sets and keyframe.
	videoSink, err := broadcast.AddBackpressuredSink()
	if err != nil {
		log.Fatalf("attach video stream: %v", err)
	}
	defer videoSink.Close()
	if err := session.StreamFrames(ctx, videoSink.AsCapture(), 0*time.Second); err != nil && ctx.Err() == nil {
		log.Printf("streaming error: %v", err)
		return
	}
	log.Println("stream ended")
}

// credentialOrPrompt returns a supplied credential or makes one pairing-display
// request and prompts once. expectPIN is true only when the receiver advertised
// an on-screen PIN (or the user explicitly requested fresh pairing). A successful
// /pair-pin-start response alone cannot distinguish a PIN from a fixed password,
// so an unadvertised fallback keeps its prompt deliberately generic.
//
// pinShown reports whether a PIN display was requested and accepted.
func credentialOrPrompt(value string, client *airplay.AirPlayClient, expectPIN bool) (credential string, pinShown bool) {
	if value != "" {
		return value, false
	}

	reader := bufio.NewReader(os.Stdin)
	displayErr := client.StartPINDisplay()
	if displayErr != nil {
		log.Printf("warning: failed to trigger PIN display: %v", displayErr)
	}
	credential = readCredential(reader, pairingCredentialPrompt(expectPIN, displayErr))
	if credential == "" {
		log.Fatal("pairing credential cannot be empty")
	}
	return credential, displayErr == nil
}

func pairingCredentialPrompt(expectPIN bool, displayErr error) string {
	if expectPIN && displayErr == nil {
		return "Enter the PIN shown on the receiver: "
	}
	return "Enter the receiver's configured password or pairing PIN: "
}

func passwordRequiresPairing(info *airplay.ReceiverInfo) bool {
	// A failed transient exchange can put a legacy password pairer into an error
	// state, so receivers advertising that pairing generation start with SRP.
	// Modern receivers retain the password only for Digest, even when their
	// status flags also advertise on-screen PIN pairing.
	return info.RequiredPairingCredential() == airplay.PairingCredentialPassword
}

func restoreSavedPairing(client *airplay.AirPlayClient, saved *airplay.SavedCredentials) error {
	return client.RestorePairingCredentials(saved)
}

func forcePairUsesTransient(info *airplay.ReceiverInfo) bool {
	return info != nil && info.RequiresPassword() &&
		info.RequiredPairingCredential() == airplay.PairingCredentialNone
}

func readCredential(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	// Read the whole line rather than using fmt.Scanln, which stops at the
	// first space and would silently truncate a password containing one.
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		log.Fatalf("failed to read credential: %v", err)
	}
	line = strings.TrimRight(line, "\r\n")
	return line
}

func selectDevice(ctx context.Context) (*airplay.AirPlayDevice, error) {
	fmt.Println("searching for Apple TVs...")
	discoverCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	devices, err := airplay.DiscoverAirPlayDevices(discoverCtx)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no Apple TVs found")
	}

	sort.Slice(devices, func(i, j int) bool {
		return compareIPs(devices[i].IP, devices[j].IP) < 0
	})

	fmt.Println("\navailable devices:")
	for i, d := range devices {
		fmt.Printf("  [%d] %s (%s) - %s\n", i+1, d.Name, d.Model, d.IP)
	}

	fmt.Print("\nselect device [1]: ")
	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)
	if input == "" {
		return &devices[0], nil
	}

	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(devices) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &devices[idx-1], nil
}

// compareIPs compares two IP address strings numerically.
func compareIPs(a, b string) int {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA == nil && ipB == nil {
		return strings.Compare(a, b)
	}
	if ipA == nil {
		return 1
	}
	if ipB == nil {
		return -1
	}
	aBytes := ipA.To16()
	bBytes := ipB.To16()
	for i := range aBytes {
		if aBytes[i] < bBytes[i] {
			return -1
		}
		if aBytes[i] > bBytes[i] {
			return 1
		}
	}
	return 0
}

func runDaemon(cfg daemon.Config) {
	d, err := daemon.New(cfg)
	if err != nil {
		log.Fatalf("[daemon] %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[daemon] shutting down...")
		cancel()
		d.Shutdown()
		<-sigCh
		log.Println("[daemon] forced exit")
		os.Exit(1)
	}()

	if err := d.Run(ctx); err != nil {
		log.Fatalf("[daemon] %v", err)
	}
}

func newCredentialStore(backend, filePath string) (*airplay.CredentialStore, error) {
	switch backend {
	case "keyring":
		kb, err := airplay.NewKeyringBackend()
		if err != nil {
			return nil, err
		}
		return airplay.NewCredentialStoreWithBackend(kb), nil
	case "file":
		return airplay.NewCredentialStore(filePath)
	default:
		return nil, fmt.Errorf("unknown credential backend %q (use \"file\" or \"keyring\")", backend)
	}
}
