package main

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

// The tests in this file run the real CLI, re-executing the test binary as
// doubletake, against a scripted device at the receiver's address. They show
// what that device is sent, which is the whole question when it is an
// impersonator.

const cliArgsEnv = "DOUBLETAKE_CLI_TEST_ARGS"

func TestMain(m *testing.M) {
	if encoded := os.Getenv(cliArgsEnv); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			fmt.Fprintf(os.Stderr, "decode CLI test arguments: %v\n", err)
			os.Exit(2)
		}
		os.Args = append([]string{"doubletake"}, args...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type scriptedRequest struct {
	conn    int
	method  string
	path    string
	headers map[string]string
	body    []byte
}

type scriptedResponse struct {
	status  int
	headers map[string]string
	body    []byte
}

// scriptedReceiver answers every connection with respond and records every
// request it is sent.
type scriptedReceiver struct {
	listener net.Listener
	respond  func(scriptedRequest) scriptedResponse
	mu       sync.Mutex
	requests []scriptedRequest
	wg       sync.WaitGroup
}

func startScriptedReceiver(t *testing.T, respond func(scriptedRequest) scriptedResponse) *scriptedReceiver {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &scriptedReceiver{listener: listener, respond: respond}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for index := 0; ; index++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			r.wg.Add(1)
			go func(conn net.Conn, index int) {
				defer r.wg.Done()
				defer conn.Close()
				r.serve(conn, index)
			}(conn, index)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		r.wg.Wait()
	})
	return r
}

func (r *scriptedReceiver) port() string {
	return strconv.Itoa(r.listener.Addr().(*net.TCPAddr).Port)
}

func (r *scriptedReceiver) serve(conn net.Conn, index int) {
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(conn)
	for {
		request, err := readScriptedRequest(reader)
		if err != nil {
			return
		}
		request.conn = index
		r.mu.Lock()
		r.requests = append(r.requests, request)
		r.mu.Unlock()
		response := r.respond(request)
		var out bytes.Buffer
		fmt.Fprintf(&out, "RTSP/1.0 %d Scripted\r\nCSeq: %s\r\n", response.status, request.headers["cseq"])
		for key, value := range response.headers {
			fmt.Fprintf(&out, "%s: %s\r\n", key, value)
		}
		fmt.Fprintf(&out, "Content-Length: %d\r\n\r\n", len(response.body))
		out.Write(response.body)
		if _, err := conn.Write(out.Bytes()); err != nil {
			return
		}
	}
}

func (r *scriptedReceiver) seen() []scriptedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]scriptedRequest(nil), r.requests...)
}

func readScriptedRequest(reader *bufio.Reader) (scriptedRequest, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return scriptedRequest{}, err
	}
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return scriptedRequest{}, fmt.Errorf("malformed request line %q", line)
	}
	request := scriptedRequest{method: parts[0], path: parts[1], headers: map[string]string{}}
	length := 0
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			return scriptedRequest{}, err
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
	request.body = make([]byte, length)
	if _, err := io.ReadFull(reader, request.body); err != nil {
		return scriptedRequest{}, err
	}
	return request, nil
}

const (
	testReceiverDeviceID = "AA:BB:CC:DD:EE:01"
	presetCode           = "preset-code"
	statusPassword       = uint64(1 << 7)
)

var (
	modernTestFeatures = airplay.FeatureSystemPairing | airplay.FeatureTransientPairing | uint64(1<<38) | uint64(1<<46)
	legacyTestFeatures = modernTestFeatures | uint64(1<<51)
)

func infoResponse(t *testing.T, deviceID string, features, statusFlags uint64) scriptedResponse {
	t.Helper()
	body, err := plist.Marshal(map[string]any{
		"name":        "Living Room",
		"model":       "AppleTV-Test",
		"deviceID":    deviceID,
		"features":    features,
		"statusFlags": statusFlags,
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("encode /info: %v", err)
	}
	return scriptedResponse{status: 200, headers: map[string]string{"Content-Type": "application/x-apple-binary-plist"}, body: body}
}

func digestChallenge() scriptedResponse {
	return scriptedResponse{status: 401, headers: map[string]string{
		"WWW-Authenticate": `Digest realm="airplay", nonce="impostor-nonce"`,
	}}
}

// pairVerifyRefused is a pair-verify V2 that carries a TLV error, as from a
// receiver that has forgotten this machine. It is not an authentication
// failure, so the saved pairing is to be paired with again with a code.
func pairVerifyRefused() scriptedResponse {
	return scriptedResponse{status: 200, headers: map[string]string{"Content-Type": "application/octet-stream"},
		body: []byte{0x06, 0x01, 0x02, 0x07, 0x01, 0x02}}
}

// savedEntry is a pairing this machine made with the receiver earlier.
func savedEntry(code airplay.PairingCode, withIdentity bool) *airplay.SavedCredentials {
	own := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	receiver := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	entry := &airplay.SavedCredentials{
		PairingID:       "12345678-1234-4234-8234-123456789abc",
		Ed25519Public:   own.Public().(ed25519.PublicKey),
		Ed25519Seed:     own.Seed(),
		PairingProtocol: airplay.PairingProtocolHAP,
		PairingCode:     code,
	}
	if withIdentity {
		entry.ReceiverID = "receiver-test-id"
		entry.ReceiverPublicKey = receiver.Public().(ed25519.PublicKey)
	}
	return entry
}

func writeCredentials(t *testing.T, entries map[string]*airplay.SavedCredentials) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type cliRun struct {
	output string
	err    error
}

// runCLI runs doubletake with args against the scripted receiver, the given
// preset code in DOUBLETAKE_CODE and stdin as what the user types.
func runCLI(t *testing.T, receiver *scriptedReceiver, credFile, code, stdin string, args ...string) cliRun {
	t.Helper()
	// -test: a run that gets past pairing must never start a real capture.
	all := append([]string{"-target", "127.0.0.1", "-port", receiver.port(), "-creds", credFile, "-no-audio", "-test"}, args...)
	encoded, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0])
	env := []string{cliArgsEnv + "=" + string(encoded)}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DOUBLETAKE_") {
			env = append(env, kv)
		}
	}
	if code != "" {
		env = append(env, "DOUBLETAKE_CODE="+code)
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("doubletake did not finish: %s", output)
	}
	return cliRun{output: string(output), err: err}
}

func requireNoAuthorization(t *testing.T, requests []scriptedRequest) {
	t.Helper()
	for _, request := range requests {
		if auth := request.headers["authorization"]; auth != "" {
			t.Fatalf("%s %s on connection %d carried Authorization %q: a Digest of the preset code "+
				"went to a device that never proved it is the paired receiver", request.method, request.path, request.conn, auth)
		}
	}
}

func countPath(requests []scriptedRequest, path string) int {
	n := 0
	for _, request := range requests {
		if request.path == path {
			n++
		}
	}
	return n
}

// A device at the address of a receiver with a saved identity challenges
// before it has proven anything. Answering would hand it an MD5 Digest of the
// code, crackable offline when the code is short.
func TestNoDigestBeforeASavedReceiverProvesItself(t *testing.T) {
	for _, test := range []struct {
		name      string
		challenge string
		// args name the receiver meant; without them it is found by the ID
		// the device reports.
		args []string
	}{
		{"challenge on /info", "/info", []string{"-device-id", testReceiverDeviceID}},
		{"challenge on pair-verify", "/pair-verify", []string{"-device-id", testReceiverDeviceID}},
		{"challenge on everything after /info", "*", []string{"-device-id", testReceiverDeviceID}},
		{"challenge on /info after reconnecting", "reconnect", []string{"-device-id", testReceiverDeviceID}},
		{"challenge on pair-verify, receiver found by its reported ID", "/pair-verify", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
				switch {
				case request.path == test.challenge:
					return digestChallenge()
				case request.path == "/info" && test.challenge == "reconnect" && request.conn > 0:
					return digestChallenge()
				case request.path == "/info":
					return infoResponse(t, testReceiverDeviceID, modernTestFeatures, 0)
				case test.challenge == "*":
					return digestChallenge()
				case request.path == "/pair-verify":
					return pairVerifyRefused()
				default:
					return digestChallenge()
				}
			})
			credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
				testReceiverDeviceID: savedEntry(airplay.PairingCodePIN, true),
			})
			run := runCLI(t, receiver, credFile, presetCode, "", test.args...)
			if run.err == nil {
				t.Fatalf("doubletake succeeded against the scripted device:\n%s", run.output)
			}
			requireNoAuthorization(t, receiver.seen())
		})
	}
}

// Pairing again with a receiver whose pairing was made with an on-screen PIN
// shows a PIN, whatever /info now claims. A device claiming to be a legacy
// pairing-password receiver used to be given the preset code -- and a Digest
// of it -- without showing anything.
func TestPairingAgainWithAPINEntryIgnoresPasswordClaims(t *testing.T) {
	for _, test := range []struct {
		name  string
		entry *airplay.SavedCredentials
	}{
		{"pin entry that will not verify", savedEntry(airplay.PairingCodePIN, true)},
		{"entry saved before receiver identities", savedEntry(airplay.PairingCodeNone, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
				switch request.path {
				case "/info":
					return infoResponse(t, testReceiverDeviceID, legacyTestFeatures, statusPassword)
				case "/pair-verify":
					return pairVerifyRefused()
				case "/pair-pin-start":
					return scriptedResponse{status: 200}
				default:
					return digestChallenge()
				}
			})
			credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{testReceiverDeviceID: test.entry})
			run := runCLI(t, receiver, credFile, presetCode, "1234\n", "-device-id", testReceiverDeviceID)
			if run.err == nil {
				t.Fatalf("doubletake succeeded against the scripted device:\n%s", run.output)
			}
			requests := receiver.seen()
			if countPath(requests, "/pair-pin-start") != 1 {
				t.Fatalf("no PIN was shown before pairing again:\n%s", run.output)
			}
			if !strings.Contains(run.output, "Enter the PIN shown on the receiver") {
				t.Fatalf("the PIN was not asked for:\n%s", run.output)
			}
			requireNoAuthorization(t, requests)
		})
	}
}

func TestPairingAgainWithAPINEntryFailsWhenNoPINIsShown(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		switch request.path {
		case "/info":
			return infoResponse(t, testReceiverDeviceID, legacyTestFeatures, statusPassword)
		case "/pair-verify":
			return pairVerifyRefused()
		default:
			return scriptedResponse{status: 500}
		}
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
		testReceiverDeviceID: savedEntry(airplay.PairingCodePIN, true),
	})
	run := runCLI(t, receiver, credFile, presetCode, "1234\n", "-device-id", testReceiverDeviceID)
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	if !strings.Contains(run.output, "if this receiver uses a pairing password rather than an on-screen code, "+
		"remove its entry from the credentials file and connect again") {
		t.Fatalf("the failure does not say what to do:\n%s", run.output)
	}
	if countPath(receiver.seen(), "/pair-setup") != 0 {
		t.Fatal("paired without the receiver showing a PIN")
	}
	requireNoAuthorization(t, receiver.seen())
}

// A pairing made with a receiver's pairing password is not made again behind
// the user's back: the password would go to whatever answers at the address.
func TestPasswordEntryIsNotPairedAgainAutomatically(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		switch request.path {
		case "/info":
			return infoResponse(t, testReceiverDeviceID, legacyTestFeatures, statusPassword)
		case "/pair-verify":
			return pairVerifyRefused()
		default:
			return digestChallenge()
		}
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
		testReceiverDeviceID: savedEntry(airplay.PairingCodePassword, true),
	})
	run := runCLI(t, receiver, credFile, presetCode, "", "-device-id", testReceiverDeviceID)
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	if !strings.Contains(run.output, "-pair") {
		t.Fatalf("the refusal does not say to run again with -pair:\n%s", run.output)
	}
	requests := receiver.seen()
	if n := countPath(requests, "/pair-setup") + countPath(requests, "/pair-pin-start"); n != 0 {
		t.Fatalf("paired again automatically (%d pairing requests)", n)
	}
	requireNoAuthorization(t, requests)
}

// With -pair the user means to pair again, and a password entry is paired
// with its password, as before.
func TestPasswordEntryIsPairedAgainWithExplicitPair(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		switch request.path {
		case "/info":
			return infoResponse(t, testReceiverDeviceID, legacyTestFeatures, statusPassword)
		default:
			return scriptedResponse{status: 500}
		}
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
		testReceiverDeviceID: savedEntry(airplay.PairingCodePassword, true),
	})
	run := runCLI(t, receiver, credFile, presetCode, "", "-device-id", testReceiverDeviceID, "-pair")
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	requests := receiver.seen()
	if countPath(requests, "/pair-setup") == 0 {
		t.Fatalf("-pair did not pair again with the password:\n%s", run.output)
	}
	if countPath(requests, "/pair-pin-start") != 0 {
		t.Fatal("-pair asked a password receiver for a PIN")
	}
}

// startCLI starts doubletake against address and stops it once done reports
// true, or after a deadline.
func startCLIUntil(t *testing.T, port int, credFile, code, stdin string, done func() bool, args ...string) string {
	t.Helper()
	all := append([]string{"-target", "127.0.0.1", "-port", strconv.Itoa(port), "-creds", credFile, "-no-audio", "-test"}, args...)
	encoded, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	env := []string{cliArgsEnv + "=" + string(encoded)}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DOUBLETAKE_") {
			env = append(env, kv)
		}
	}
	if code != "" {
		env = append(env, "DOUBLETAKE_CODE="+code)
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	deadline := time.After(15 * time.Second)
	for !done() {
		select {
		case <-exited:
			return output.String()
		case <-deadline:
			_ = cmd.Process.Kill()
			<-exited
			t.Fatalf("doubletake did not get there in time:\n%s", output.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	_ = cmd.Process.Kill()
	<-exited
	return output.String()
}

// A first pairing records the kind of code it was made with, which decides
// how the receiver is paired with again.
func TestFirstPairingRecordsTheKindOfCode(t *testing.T) {
	for _, test := range []struct {
		name    string
		profile airplay.ReceiverProfile
		auth    airplay.ReceiverAuthMode
		preset  string
		stdin   string
		want    airplay.PairingCode
	}{
		{"on-screen PIN", airplay.ReceiverProfileModern, airplay.ReceiverAuthPIN, "", "4827\n", airplay.PairingCodePIN},
		{"pairing password", airplay.ReceiverProfileRoku, airplay.ReceiverAuthPassword, "4827", "", airplay.PairingCodePassword},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
				ListenAddress: "127.0.0.1:0",
				Profile:       test.profile,
				Auth:          test.auth,
				Code:          "4827",
				DeviceID:      testReceiverDeviceID,
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
			saved := func() *airplay.SavedCredentials {
				store, err := airplay.NewCredentialStore(credFile)
				if err != nil {
					return nil
				}
				return store.Lookup(testReceiverDeviceID)
			}
			output := startCLIUntil(t, server.Addr().(*net.TCPAddr).Port, credFile, test.preset, test.stdin,
				func() bool { return saved().HasReceiverIdentity() })
			entry := saved()
			if !entry.HasReceiverIdentity() {
				t.Fatalf("no pairing was saved:\n%s", output)
			}
			if entry.PairingCode != test.want {
				t.Fatalf("pairing_code = %q, want %q", entry.PairingCode, test.want)
			}
			if entry.PairedAt == "" {
				t.Fatal("paired_at was not saved")
			}
			if entry.ReceiverAddress != "127.0.0.1" {
				t.Fatalf("receiver_address = %q, want the -target host", entry.ReceiverAddress)
			}
		})
	}
}

// Holding the password back until the receiver proves itself must not cost
// the real receiver its Digest: once pair-verify succeeds, SETUP is answered.
// Named by -device-id, or by the address it was paired at.
func TestSavedReceiverGetsThePasswordOnceVerified(t *testing.T) {
	t.Run("-device-id", func(t *testing.T) {
		testSavedReceiverGetsThePasswordOnceVerified(t, "-device-id", testReceiverDeviceID)
	})
	t.Run("address", func(t *testing.T) { testSavedReceiverGetsThePasswordOnceVerified(t) })
}

func testSavedReceiverGetsThePasswordOnceVerified(t *testing.T, args ...string) {
	// Reaching RECORD starts the synthetic capture.
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("gst-launch-1.0 is required to reach RECORD")
	}
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		t.Skip("GStreamer openh264enc is required to reach RECORD")
	}
	args = append([]string{"-hwaccel", "openh264"}, args...)
	const code = "combined password"
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0",
		Profile:       airplay.ReceiverProfileRoku,
		Auth:          airplay.ReceiverAuthCombined,
		Code:          code,
		DeviceID:      testReceiverDeviceID,
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
	port := server.Addr().(*net.TCPAddr).Port
	credFile := filepath.Join(t.TempDir(), "credentials.json")

	paired := func() bool {
		store, err := airplay.NewCredentialStore(credFile)
		return err == nil && store.Lookup(testReceiverDeviceID).HasReceiverIdentity()
	}
	output := startCLIUntil(t, port, credFile, code, "", paired, args...)
	if !paired() {
		t.Fatalf("first run saved no pairing:\n%s", output)
	}

	before := server.Stats()
	recorded := func() bool { return server.Stats().RecordRequests > before.RecordRequests }
	output = startCLIUntil(t, port, credFile, code, "", recorded, args...)
	after := server.Stats()
	if !recorded() {
		t.Fatalf("second run did not reach RECORD:\n%s", output)
	}
	if after.PairSetup != before.PairSetup {
		t.Fatalf("second run paired again (%d pair-setup requests) instead of verifying", after.PairSetup-before.PairSetup)
	}
	if after.DigestChallenges == before.DigestChallenges {
		t.Fatal("second run was never challenged; this test no longer shows the Digest being answered")
	}
}

const boundDeviceID = "AA:BB:CC:DD:EE:0B"

// boundEntry is a pairing made with a receiver at 127.0.0.1 earlier.
func boundEntry() *airplay.SavedCredentials {
	entry := savedEntry(airplay.PairingCodePIN, true)
	entry.ReceiverAddress = "127.0.0.1"
	entry.PairedAt = "2026-10-01T10:00:00Z"
	return entry
}

// A receiver reached by address alone is the one paired at that address. A
// device that takes the address over and names itself as a receiver never
// seen, needing no code, used to be paired with transiently and given the
// screen.
func TestDeviceAtABoundAddressNamingItselfAnewIsRefused(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		if request.path == "/info" {
			return infoResponse(t, "11:22:33:44:55:66", modernTestFeatures, 0)
		}
		return scriptedResponse{status: 500}
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{boundDeviceID: boundEntry()})
	run := runCLI(t, receiver, credFile, "", "")
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	if !strings.Contains(run.output, "if a different receiver now has that address, pair with it explicitly") ||
		!strings.Contains(run.output, "-pair") {
		t.Fatalf("the refusal does not say what to do:\n%s", run.output)
	}
	if strings.Contains(run.output, "warning: no -device-id") {
		t.Fatalf("warned of no -device-id although the address names the receiver:\n%s", run.output)
	}
	for _, request := range receiver.seen() {
		if request.path != "/info" {
			t.Fatalf("sent %s %s to a device refused at a bound address", request.method, request.path)
		}
	}
}

// Without -device-id or a receiver paired at the address, the device at
// -target is taken at its word, as before, with a warning.
func TestNoAddressBindingKeepsTheOldBehaviour(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		if request.path == "/info" {
			return infoResponse(t, "11:22:33:44:55:66", modernTestFeatures, 0)
		}
		return scriptedResponse{status: 500}
	})
	elsewhere := boundEntry()
	elsewhere.ReceiverAddress = "192.0.2.7"
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{boundDeviceID: elsewhere})
	run := runCLI(t, receiver, credFile, "", "")
	if !strings.Contains(run.output, "warning: no -device-id") {
		t.Fatalf("no warning that the device is taken at its word:\n%s", run.output)
	}
	if countPath(receiver.seen(), "/pair-setup") == 0 {
		t.Fatalf("did not pair with the device at -target as before:\n%s", run.output)
	}
}

// -pair is the user pairing deliberately with whatever is at the address now:
// the binding does not refuse it, and the new pairing takes the address over.
func TestPairTakesABoundAddressOver(t *testing.T) {
	const newID = "11:22:33:44:55:66"
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0",
		Profile:       airplay.ReceiverProfileModern,
		Auth:          airplay.ReceiverAuthPIN,
		Code:          "4827",
		DeviceID:      newID,
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
	port := server.Addr().(*net.TCPAddr).Port
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{boundDeviceID: boundEntry()})
	load := func() *airplay.CredentialStore {
		store, err := airplay.NewCredentialStore(credFile)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}

	// Without -pair the new receiver is refused: it is not the one paired here.
	output := startCLIUntil(t, port, credFile, "", "4827\n", func() bool { return false })
	if !strings.Contains(output, "refusing to cast") {
		t.Fatalf("the receiver now at the bound address was not refused:\n%s", output)
	}

	paired := func() bool { return load().Lookup(newID).HasReceiverIdentity() }
	output = startCLIUntil(t, port, credFile, "", "4827\n", paired, "-pair")
	if !paired() {
		t.Fatalf("-pair did not pair with the receiver at the address:\n%s", output)
	}
	store := load()
	if got := store.Lookup(newID).ReceiverAddress; got != "127.0.0.1" {
		t.Fatalf("new pairing's receiver_address = %q, want 127.0.0.1", got)
	}
	if got := store.Lookup(boundDeviceID); got.ReceiverAddress != "" || !got.HasReceiverIdentity() {
		t.Fatalf("old receiver after the address was taken over = %+v, want its pairing without the address", got)
	}
	if bound, _, _ := store.ReceiverAtAddress("127.0.0.1"); bound != newID {
		t.Fatalf("receiver at the address = %q, want %q", bound, newID)
	}
}

// Two entries at one address, as castr's copying between mode files can
// leave: the newest pairing is the receiver meant.
func TestNewestPairingAtAnAddressIsTheReceiverMeant(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		if request.path == "/info" {
			return infoResponse(t, "11:22:33:44:55:66", modernTestFeatures, 0)
		}
		return scriptedResponse{status: 500}
	})
	stale := boundEntry()
	stale.PairedAt = "2026-09-01T10:00:00Z"
	t.Run("newest names another receiver", func(t *testing.T) {
		credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
			boundDeviceID: boundEntry(), "11:22:33:44:55:66": stale,
		})
		run := runCLI(t, receiver, credFile, "", "")
		if !strings.Contains(run.output, "if a different receiver now has that address") {
			t.Fatalf("the newest pairing at the address was not the receiver meant:\n%s", run.output)
		}
	})
	// A tie fails closed: either tied receiver may answer, a fresh ID may
	// not -- it used to be paired with from scratch.
	t.Run("tie, a third receiver answers", func(t *testing.T) {
		tie := boundEntry()
		credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
			boundDeviceID: boundEntry(), "11:22:33:44:55:01": tie,
		})
		run := runCLI(t, receiver, credFile, "", "")
		if run.err == nil || !strings.Contains(run.output, boundDeviceID) || !strings.Contains(run.output, "11:22:33:44:55:01") ||
			!strings.Contains(run.output, "remove the stale entry") {
			t.Fatalf("a tie did not refuse a third receiver, naming both tied ones:\n%s", run.output)
		}
		if strings.Contains(run.output, "warning: no -device-id") {
			t.Fatalf("a tie fell back to no binding:\n%s", run.output)
		}
		for _, request := range receiver.seen() {
			if request.path != "/info" {
				t.Fatalf("sent %s %s to a device that is neither tied receiver", request.method, request.path)
			}
		}
	})
}

// A tied receiver answering as itself is the receiver meant, and like any
// bound receiver must prove itself before the password goes anywhere.
func TestTiedReceiverAtAnAddressMustProveItself(t *testing.T) {
	const tiedID = "11:22:33:44:55:01"
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		if request.path == "/info" && request.conn == 0 {
			return infoResponse(t, tiedID, modernTestFeatures, 0)
		}
		return digestChallenge()
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
		boundDeviceID: boundEntry(), tiedID: boundEntry(),
	})
	run := runCLI(t, receiver, credFile, presetCode, "")
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	if strings.Contains(run.output, "remove the stale entry") || strings.Contains(run.output, "warning: no -device-id") {
		t.Fatalf("a tied receiver answering as itself was not taken as the receiver meant:\n%s", run.output)
	}
	if countPath(receiver.seen(), "/pair-verify") == 0 {
		t.Fatalf("the tied receiver was not asked to prove itself:\n%s", run.output)
	}
	requireNoAuthorization(t, receiver.seen())
}

// Before /info says which tied receiver answers, the address still names
// receivers this machine paired with: the password is held back.
func TestNoDigestBeforeATiedAddressSaysWhoAnswers(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		return digestChallenge()
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
		boundDeviceID: boundEntry(), "11:22:33:44:55:01": boundEntry(),
	})
	run := runCLI(t, receiver, credFile, presetCode, "")
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	if len(receiver.seen()) == 0 {
		t.Fatal("the device was never asked anything")
	}
	requireNoAuthorization(t, receiver.seen())
}

// A code-made pairing saved before receiver identities has nothing to verify
// against, but the receiver meant is still one this machine paired with: the
// preset code is held back from whatever answers until it pairs again with a
// code.
func TestNoDigestForAPairingSavedBeforeIdentities(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		if request.path == "/info" && request.headers["authorization"] == "" {
			return digestChallenge()
		}
		if request.path == "/info" {
			return infoResponse(t, testReceiverDeviceID, modernTestFeatures, 0)
		}
		return scriptedResponse{status: 500}
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
		testReceiverDeviceID: savedEntry(airplay.PairingCodeNone, false),
	})
	run := runCLI(t, receiver, credFile, presetCode, "", "-device-id", testReceiverDeviceID)
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	requireNoAuthorization(t, receiver.seen())
}

func rawEntryBeforeIdentities() *airplay.SavedCredentials {
	entry := savedEntry(airplay.PairingCodeNone, false)
	entry.PairingProtocol = airplay.PairingProtocolRaw
	return entry
}

// A raw pairing saved before identities is paired with again raw: it took no
// code, so none is offered, whatever /info now claims. The preset code went
// into SRP pair-setup, and a Digest of it to a 401, when /info claimed a
// legacy pairing password.
func TestRawPairingBeforeIdentitiesIsPairedAgainOnlyRaw(t *testing.T) {
	for _, test := range []struct {
		name               string
		features, status   uint64
		wantNoPairingSetup bool
	}{
		{"device claims a legacy pairing password", legacyTestFeatures, statusPassword, true},
		{"device claims an on-screen PIN", modernTestFeatures, 1 << 9, true},
		{"device claims nothing but will not pair raw", modernTestFeatures, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
				switch request.path {
				case "/info":
					return infoResponse(t, testReceiverDeviceID, test.features, test.status)
				case "/pair-setup":
					return scriptedResponse{status: 500}
				default:
					return digestChallenge()
				}
			})
			credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{testReceiverDeviceID: rawEntryBeforeIdentities()})
			run := runCLI(t, receiver, credFile, presetCode, "", "-device-id", testReceiverDeviceID)
			if run.err == nil {
				t.Fatalf("doubletake succeeded:\n%s", run.output)
			}
			if !strings.Contains(run.output, "remove its entry from the credentials file") {
				t.Fatalf("the refusal does not say what to do:\n%s", run.output)
			}
			requests := receiver.seen()
			requireNoAuthorization(t, requests)
			if countPath(requests, "/pair-pin-start") != 0 {
				t.Fatal("asked a receiver paired with raw for a PIN")
			}
			for _, request := range requests {
				if request.path != "/pair-setup" {
					continue
				}
				if test.wantNoPairingSetup {
					t.Fatalf("pair-setup sent to a device asking for a code the receiver never took")
				}
				// Raw pair-setup is our 32-byte key and nothing else: no SRP,
				// no transient TLV8.
				if len(request.body) != 32 {
					t.Fatalf("pair-setup body is %d bytes, not raw pair-setup", len(request.body))
				}
			}
		})
	}
}

// The real raw receiver is paired with again, raw, as at a first contact,
// and the new pairing replaces the old entry with the key it recorded, so
// later runs verify against it.
func TestRawPairingBeforeIdentitiesIsSavedWithTheReceiversKey(t *testing.T) {
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0",
		Profile:       airplay.ReceiverProfileAppleTV3,
		DeviceID:      testReceiverDeviceID,
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
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{testReceiverDeviceID: rawEntryBeforeIdentities()})
	saved := func() *airplay.SavedCredentials {
		store, err := airplay.NewCredentialStore(credFile)
		if err != nil {
			return nil
		}
		return store.Lookup(testReceiverDeviceID)
	}
	output := startCLIUntil(t, server.Addr().(*net.TCPAddr).Port, credFile, presetCode, "",
		func() bool { return saved().HasReceiverIdentity() }, "-device-id", testReceiverDeviceID)
	entry := saved()
	if !entry.HasReceiverIdentity() || !entry.UsesRawPairing() {
		t.Fatalf("saved %+v, want a raw pairing with the receiver's key:\n%s", entry, output)
	}
	if entry.PairingCode != airplay.PairingCodeNone || entry.PairedAt == "" || entry.ReceiverAddress != "127.0.0.1" {
		t.Fatalf("saved pairing_code %q paired_at %q receiver_address %q, want none, a time and 127.0.0.1",
			entry.PairingCode, entry.PairedAt, entry.ReceiverAddress)
	}
	if stats := server.Stats(); stats.PairSetup != 1 || stats.PINStarts != 0 {
		t.Fatalf("pairing requests %+v, want one raw pair-setup", stats)
	}

	// The test receiver keeps no raw pairing past its connection, as a
	// replaced device would not: the next run is checked against the saved
	// key, fails, and is refused rather than paired with again.
	run := runScriptlessCLI(t, server.Addr().(*net.TCPAddr).Port, credFile, presetCode, "-device-id", testReceiverDeviceID)
	if run.err == nil || !strings.Contains(run.output, "refusing to replace the saved pairing") {
		t.Fatalf("a raw receiver that no longer verifies was not refused:\n%s", run.output)
	}
	if server.Stats().PairSetup != 1 {
		t.Fatal("a raw receiver that no longer verifies was paired with again")
	}
}

// A pairing saved before addresses were recorded is bound to the address
// once the receiver proves its saved identity there, and only then.
func TestProvenReceiverIsBoundToItsAddress(t *testing.T) {
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0",
		Profile:       airplay.ReceiverProfileModern,
		Auth:          airplay.ReceiverAuthPIN,
		Code:          "4827",
		DeviceID:      testReceiverDeviceID,
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
	port := server.Addr().(*net.TCPAddr).Port
	credFile := filepath.Join(t.TempDir(), "credentials.json")
	load := func() *airplay.CredentialStore {
		store, err := airplay.NewCredentialStore(credFile)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	paired := func() bool { return load().Lookup(testReceiverDeviceID).HasReceiverIdentity() }
	startCLIUntil(t, port, credFile, "", "4827\n", paired)
	if !paired() {
		t.Fatal("first run did not pair")
	}

	// As saved before receiver_address existed, with a stale entry holding
	// the address.
	var entries map[string]*airplay.SavedCredentials
	data, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	entries[testReceiverDeviceID].ReceiverAddress = ""
	entries[testReceiverDeviceID].PairedAt = ""
	stale := boundEntry()
	stale.ReceiverAddress = "192.0.2.1"
	entries[boundDeviceID] = stale
	data, err = json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	before := server.Stats()
	bound := func() bool { return load().Lookup(testReceiverDeviceID).ReceiverAddress == "127.0.0.1" }
	output := startCLIUntil(t, port, credFile, "", "", bound, "-device-id", testReceiverDeviceID)
	if !bound() {
		t.Fatalf("a receiver that proved itself by address was not bound to it:\n%s", output)
	}
	if server.Stats().PairSetup != before.PairSetup {
		t.Fatal("the second run paired again instead of verifying")
	}
	if got := load().Lookup(testReceiverDeviceID).PairedAt; got != "" {
		t.Fatalf("binding changed paired_at to %q", got)
	}
}

// Nothing is bound after a pair-verify that did not prove the receiver.
func TestUnprovenReceiverIsNotBoundToItsAddress(t *testing.T) {
	receiver := startScriptedReceiver(t, func(request scriptedRequest) scriptedResponse {
		switch request.path {
		case "/info":
			return infoResponse(t, testReceiverDeviceID, modernTestFeatures, 0)
		case "/pair-verify":
			return pairVerifyRefused()
		default:
			return scriptedResponse{status: 500}
		}
	})
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{
		testReceiverDeviceID: savedEntry(airplay.PairingCodePIN, true),
	})
	run := runCLI(t, receiver, credFile, "", "1234\n", "-device-id", testReceiverDeviceID)
	if run.err == nil {
		t.Fatalf("doubletake succeeded:\n%s", run.output)
	}
	store, err := airplay.NewCredentialStore(credFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Lookup(testReceiverDeviceID).ReceiverAddress; got != "" {
		t.Fatalf("an unproven device's address %q was bound to the receiver", got)
	}
}

// A raw receiver paired with again gets the preset code for its Digest, as at
// a first contact; before, it failed at the first challenge on every run.
func TestRawRepairReleasesThePresetCodeLikeAFirstContact(t *testing.T) {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("gst-launch-1.0 is required to reach RECORD")
	}
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		t.Skip("GStreamer openh264enc is required to reach RECORD")
	}
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0",
		Profile:       airplay.ReceiverProfileAppleTV3,
		Auth:          airplay.ReceiverAuthDigest,
		Code:          presetCode,
		// Its /info claims no code; it challenges after pairing.
		HidePasswordStatus: true,
		DeviceID:           testReceiverDeviceID,
		Logger:             log.New(io.Discard, "", 0),
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
	credFile := writeCredentials(t, map[string]*airplay.SavedCredentials{testReceiverDeviceID: rawEntryBeforeIdentities()})
	recorded := func() bool { return server.Stats().RecordRequests > 0 }
	output := startCLIUntil(t, server.Addr().(*net.TCPAddr).Port, credFile, presetCode, "", recorded,
		"-device-id", testReceiverDeviceID, "-hwaccel", "openh264")
	if !recorded() {
		t.Fatalf("the raw receiver paired with again did not get the preset code for its Digest:\n%s", output)
	}
	if stats := server.Stats(); stats.PairSetup != 1 || stats.DigestChallenges == 0 {
		t.Fatalf("receiver stats %+v, want one raw pair-setup and a Digest answered", stats)
	}
}

// runScriptlessCLI runs doubletake to completion against a receiver at port.
func runScriptlessCLI(t *testing.T, port int, credFile, code string, args ...string) cliRun {
	t.Helper()
	all := append([]string{"-target", "127.0.0.1", "-port", strconv.Itoa(port), "-creds", credFile, "-no-audio", "-test"}, args...)
	encoded, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0])
	env := []string{cliArgsEnv + "=" + string(encoded)}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DOUBLETAKE_") {
			env = append(env, kv)
		}
	}
	if code != "" {
		env = append(env, "DOUBLETAKE_CODE="+code)
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader("")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("doubletake did not finish: %s", output)
	}
	return cliRun{output: string(output), err: err}
}
