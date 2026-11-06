package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"doubletake/internal/airplay"
	"howett.net/plist"
)

// These tests put a scripted device at the address of a receiver the daemon
// has a saved pairing for, and look at what it is sent.

type savedPairingRequest struct {
	conn    int
	method  string
	path    string
	headers map[string]string
}

type savedPairingDevice struct {
	listener net.Listener
	mu       sync.Mutex
	requests []savedPairingRequest
	wg       sync.WaitGroup
}

func startSavedPairingDevice(t *testing.T, respond func(conn int, path string) (int, map[string]string, []byte)) *savedPairingDevice {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	device := &savedPairingDevice{listener: listener}
	device.wg.Add(1)
	go func() {
		defer device.wg.Done()
		for index := 0; ; index++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			device.wg.Add(1)
			go func(conn net.Conn, index int) {
				defer device.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				reader := bufio.NewReader(conn)
				for {
					request, err := readSavedPairingRequest(reader)
					if err != nil {
						return
					}
					request.conn = index
					device.mu.Lock()
					device.requests = append(device.requests, request)
					device.mu.Unlock()
					status, headers, body := respond(index, request.path)
					var out bytes.Buffer
					fmt.Fprintf(&out, "RTSP/1.0 %d Scripted\r\nCSeq: %s\r\n", status, request.headers["cseq"])
					for key, value := range headers {
						fmt.Fprintf(&out, "%s: %s\r\n", key, value)
					}
					fmt.Fprintf(&out, "Content-Length: %d\r\n\r\n", len(body))
					out.Write(body)
					if _, err := conn.Write(out.Bytes()); err != nil {
						return
					}
				}
			}(conn, index)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		device.wg.Wait()
	})
	return device
}

func readSavedPairingRequest(reader *bufio.Reader) (savedPairingRequest, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return savedPairingRequest{}, err
	}
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return savedPairingRequest{}, fmt.Errorf("malformed request line %q", line)
	}
	request := savedPairingRequest{method: parts[0], path: parts[1], headers: map[string]string{}}
	length := 0
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			return savedPairingRequest{}, err
		}
		header = strings.TrimSpace(header)
		if header == "" {
			break
		}
		name, value, _ := strings.Cut(header, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		request.headers[name] = strings.TrimSpace(value)
		if name == "content-length" {
			length, _ = strconv.Atoi(request.headers[name])
		}
	}
	if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
		return savedPairingRequest{}, err
	}
	return request, nil
}

func (device *savedPairingDevice) seen() []savedPairingRequest {
	device.mu.Lock()
	defer device.mu.Unlock()
	return append([]savedPairingRequest(nil), device.requests...)
}

func (device *savedPairingDevice) count(path string) int {
	n := 0
	for _, request := range device.seen() {
		if request.path == path {
			n++
		}
	}
	return n
}

func (device *savedPairingDevice) requireNoAuthorization(t *testing.T) {
	t.Helper()
	for _, request := range device.seen() {
		if auth := request.headers["authorization"]; auth != "" {
			t.Fatalf("%s %s on connection %d carried Authorization %q: a Digest of the preset code went "+
				"to a device that never proved it is the paired receiver", request.method, request.path, request.conn, auth)
		}
	}
}

const savedPairingDeviceID = "AA:BB:CC:DD:EE:01"

var (
	savedPairingModernFeatures = airplay.FeatureSystemPairing | airplay.FeatureTransientPairing | uint64(1<<38) | uint64(1<<46)
	savedPairingLegacyFeatures = savedPairingModernFeatures | uint64(1<<51)
)

func savedPairingInfo(t *testing.T, features, statusFlags uint64) []byte {
	t.Helper()
	body, err := plist.Marshal(map[string]any{
		"name":        "Living Room",
		"model":       "AppleTV-Test",
		"deviceID":    savedPairingDeviceID,
		"features":    features,
		"statusFlags": statusFlags,
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

var (
	digestChallengeHeaders = map[string]string{"WWW-Authenticate": `Digest realm="airplay", nonce="impostor-nonce"`}
	// A pair-verify V2 carrying a TLV error: the receiver has forgotten this
	// machine. Not an authentication failure, so the daemon pairs again.
	pairVerifyRefusedBody = []byte{0x06, 0x01, 0x02, 0x07, 0x01, 0x02}
)

func savedPairingDaemon(t *testing.T, code airplay.PairingCode) *Daemon {
	t.Helper()
	return savedPairingDaemonAt(t, code, "")
}

// savedPairingDaemonAt is savedPairingDaemon with the pairing made at address.
func savedPairingDaemonAt(t *testing.T, code airplay.PairingCode, address string) *Daemon {
	t.Helper()
	own := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	receiver := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	entries := map[string]*airplay.SavedCredentials{savedPairingDeviceID: {
		PairingID:         "12345678-1234-4234-8234-123456789abc",
		Ed25519Public:     own.Public().(ed25519.PublicKey),
		Ed25519Seed:       own.Seed(),
		PairingProtocol:   airplay.PairingProtocolHAP,
		ReceiverID:        "receiver-test-id",
		ReceiverPublicKey: receiver.Public().(ed25519.PublicKey),
		PairingCode:       code,
		ReceiverAddress:   address,
		PairedAt:          "2026-10-01T10:00:00Z",
	}}
	path := filepath.Join(t.TempDir(), "credentials.json")
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{CredBackend: "file", CredFile: path, NoAudio: true, Code: "preset-code"})
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	t.Cleanup(d.Shutdown)
	return d
}

func connectSavedPairing(t *testing.T, d *Daemon, device *savedPairingDevice) {
	t.Helper()
	port := device.listener.Addr().(*net.TCPAddr).Port
	response := d.handleConnect(Request{Cmd: "connect", Target: "127.0.0.1", Port: port, DeviceID: savedPairingDeviceID})
	if !response.OK {
		t.Fatalf("connect rejected: %+v", response)
	}
}

func waitForSavedPairingError(t *testing.T, d *Daemon) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if status := d.handleStatus(); status.State == StateIdle && status.Error != "" {
			return status.Error
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("daemon did not fail: %+v", d.handleStatus())
	return ""
}

func TestDaemonSendsNoDigestBeforeASavedReceiverProvesItself(t *testing.T) {
	for _, challenge := range []string{"/info", "/pair-verify", "/info after reconnecting"} {
		t.Run(challenge, func(t *testing.T) {
			info := savedPairingInfo(t, savedPairingModernFeatures, 0)
			device := startSavedPairingDevice(t, func(conn int, path string) (int, map[string]string, []byte) {
				switch {
				case path == "/info" && (challenge == "/pair-verify" || challenge != "/info" && conn == 0):
					return 200, map[string]string{"Content-Type": "application/x-apple-binary-plist"}, info
				case path == "/pair-verify" && challenge == "/info after reconnecting":
					return 200, map[string]string{"Content-Type": "application/octet-stream"}, pairVerifyRefusedBody
				}
				return 401, digestChallengeHeaders, nil
			})
			d := savedPairingDaemon(t, airplay.PairingCodePIN)
			connectSavedPairing(t, d, device)
			waitForSavedPairingError(t, d)
			device.requireNoAuthorization(t)
		})
	}
}

func TestDaemonPairsAgainWithAPINWhateverInfoClaims(t *testing.T) {
	info := savedPairingInfo(t, savedPairingLegacyFeatures, 1<<7)
	device := startSavedPairingDevice(t, func(conn int, path string) (int, map[string]string, []byte) {
		switch path {
		case "/info":
			return 200, map[string]string{"Content-Type": "application/x-apple-binary-plist"}, info
		case "/pair-verify":
			return 200, map[string]string{"Content-Type": "application/octet-stream"}, pairVerifyRefusedBody
		case "/pair-pin-start":
			return 200, nil, nil
		default:
			return 401, digestChallengeHeaders, nil
		}
	})
	d := savedPairingDaemon(t, airplay.PairingCodePIN)
	connectSavedPairing(t, d, device)
	pinFlowWaitForState(t, d, StatePINRequired)
	if status := d.handleStatus(); status.CredentialKind != CredentialKindPIN {
		t.Fatalf("waiting for %q, want a PIN", status.CredentialKind)
	}
	if device.count("/pair-pin-start") != 1 {
		t.Fatal("no PIN was shown before pairing again")
	}
	if response := d.handleConnect(Request{Cmd: "connect", Pin: "1234"}); !response.OK {
		t.Fatalf("PIN submission rejected: %+v", response)
	}
	waitForSavedPairingError(t, d)
	if device.count("/pair-setup") == 0 {
		t.Fatal("the typed PIN was not used to pair")
	}
	device.requireNoAuthorization(t)
}

func TestDaemonDoesNotPairAgainWithAPasswordAutomatically(t *testing.T) {
	info := savedPairingInfo(t, savedPairingLegacyFeatures, 1<<7)
	device := startSavedPairingDevice(t, func(conn int, path string) (int, map[string]string, []byte) {
		switch path {
		case "/info":
			return 200, map[string]string{"Content-Type": "application/x-apple-binary-plist"}, info
		case "/pair-verify":
			return 200, map[string]string{"Content-Type": "application/octet-stream"}, pairVerifyRefusedBody
		default:
			return 401, digestChallengeHeaders, nil
		}
	})
	d := savedPairingDaemon(t, airplay.PairingCodePassword)
	connectSavedPairing(t, d, device)
	failure := waitForSavedPairingError(t, d)
	if !strings.Contains(failure, "refusing to pair with") {
		t.Fatalf("failure = %q, want a refusal to pair again", failure)
	}
	if n := device.count("/pair-setup") + device.count("/pair-pin-start"); n != 0 {
		t.Fatalf("paired again automatically (%d pairing requests)", n)
	}
	device.requireNoAuthorization(t)
}

// A first pairing records the kind of code it was made with, which decides
// how the receiver is paired with again.
func TestDaemonFirstPairingRecordsTheKindOfCode(t *testing.T) {
	for _, test := range []struct {
		name    string
		profile airplay.ReceiverProfile
		auth    airplay.ReceiverAuthMode
		want    airplay.PairingCode
	}{
		{"on-screen PIN", airplay.ReceiverProfileModern, airplay.ReceiverAuthPIN, airplay.PairingCodePIN},
		{"pairing password", airplay.ReceiverProfileRoku, airplay.ReceiverAuthPassword, airplay.PairingCodePassword},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
				ListenAddress: "127.0.0.1:0",
				Profile:       test.profile,
				Auth:          test.auth,
				Code:          "4827",
				DeviceID:      savedPairingDeviceID,
				Logger:        log.New(io.Discard, "", 0),
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			served := make(chan error, 1)
			go func() { served <- server.Serve(ctx) }()
			t.Cleanup(func() {
				cancel()
				_ = server.Close()
				<-served
			})

			credFile := filepath.Join(t.TempDir(), "credentials.json")
			d, err := New(Config{CredBackend: "file", CredFile: credFile, NoAudio: true, NoEncrypt: true,
				TestMode: true, HWAccel: "openh264", FPS: 10, Bitrate: 500})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(d.Shutdown)
			addr := server.Addr().(*net.TCPAddr)
			if response := d.handleConnect(Request{Cmd: "connect", Target: addr.IP.String(), Port: addr.Port}); !response.OK {
				t.Fatalf("connect rejected: %+v", response)
			}
			pinFlowWaitForState(t, d, StatePINRequired)
			if response := d.handleConnect(Request{Cmd: "connect", Pin: "4827"}); !response.OK {
				t.Fatalf("code submission rejected: %+v", response)
			}

			var entry *airplay.SavedCredentials
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if store, err := airplay.NewCredentialStore(credFile); err == nil {
					if entry = store.Lookup(savedPairingDeviceID); entry.HasReceiverIdentity() {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !entry.HasReceiverIdentity() {
				t.Fatalf("no pairing was saved: %+v", d.handleStatus())
			}
			if entry.PairingCode != test.want || entry.PairedAt == "" {
				t.Fatalf("saved pairing_code %q paired_at %q, want %q and a time", entry.PairingCode, entry.PairedAt, test.want)
			}
			if entry.ReceiverAddress != addr.IP.String() {
				t.Fatalf("saved receiver_address %q, want %q", entry.ReceiverAddress, addr.IP.String())
			}
		})
	}
}

// Holding the password back until the receiver proves itself must not cost
// the real receiver its Digest: once pair-verify succeeds, SETUP is answered.
func TestDaemonSavedReceiverGetsThePasswordOnceVerified(t *testing.T) {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("gst-launch-1.0 is required to start streaming")
	}
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		t.Skip("GStreamer openh264enc is required to start streaming")
	}
	const code = "combined password"
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0",
		Profile:       airplay.ReceiverProfileRoku,
		Auth:          airplay.ReceiverAuthCombined,
		Code:          code,
		DeviceID:      savedPairingDeviceID,
		Logger:        log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		<-served
	})

	d, err := New(Config{CredBackend: "file", CredFile: filepath.Join(t.TempDir(), "credentials.json"),
		NoAudio: true, TestMode: true, HWAccel: "openh264", FPS: 10, Bitrate: 500, Code: code})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Shutdown)
	addr := server.Addr().(*net.TCPAddr)
	connect := func() {
		t.Helper()
		if response := d.handleConnect(Request{Cmd: "connect", Target: addr.IP.String(), Port: addr.Port,
			DeviceID: savedPairingDeviceID}); !response.OK {
			t.Fatalf("connect rejected: %+v", response)
		}
		pinFlowWaitForState(t, d, StateStreaming)
	}
	connect()
	if response := d.handleDisconnect(Request{Cmd: "disconnect", Target: addr.IP.String()}); !response.OK {
		t.Fatalf("disconnect rejected: %+v", response)
	}
	pinFlowWaitForState(t, d, StateIdle)

	before := server.Stats()
	connect()
	after := server.Stats()
	if after.PairSetup != before.PairSetup {
		t.Fatalf("second connect paired again (%d pair-setup requests) instead of verifying", after.PairSetup-before.PairSetup)
	}
	if after.DigestChallenges == before.DigestChallenges {
		t.Fatal("second connect was never challenged; this test no longer shows the Digest being answered")
	}
}

// A receiver reached by address alone is the one paired at that address; a
// device there naming itself as a receiver never seen is refused.
func TestDaemonRefusesADeviceAtABoundAddressNamingItselfAnew(t *testing.T) {
	info, err := plist.Marshal(map[string]any{
		"name": "Impostor", "model": "AppleTV-Test", "deviceID": "11:22:33:44:55:66",
		"features": savedPairingModernFeatures, "statusFlags": uint64(0),
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	device := startSavedPairingDevice(t, func(conn int, path string) (int, map[string]string, []byte) {
		if path == "/info" {
			return 200, map[string]string{"Content-Type": "application/x-apple-binary-plist"}, info
		}
		return 500, nil, nil
	})
	d := savedPairingDaemonAt(t, airplay.PairingCodePIN, "127.0.0.1")
	port := device.listener.Addr().(*net.TCPAddr).Port
	if response := d.handleConnect(Request{Cmd: "connect", Target: "127.0.0.1", Port: port}); !response.OK {
		t.Fatalf("connect rejected: %+v", response)
	}
	failure := waitForSavedPairingError(t, d)
	if !strings.Contains(failure, "if a different receiver now has that address") {
		t.Fatalf("failure = %q, want a refusal naming the receiver paired at the address", failure)
	}
	for _, request := range device.seen() {
		if request.path != "/info" {
			t.Fatalf("sent %s %s to a device refused at a bound address", request.method, request.path)
		}
	}
}
