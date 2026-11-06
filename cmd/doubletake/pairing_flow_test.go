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
	all := append([]string{"-target", "127.0.0.1", "-port", receiver.port(), "-creds", credFile, "-no-audio"}, args...)
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
		})
	}
}

// Holding the password back until the receiver proves itself must not cost
// the real receiver its Digest: once pair-verify succeeds, SETUP is answered.
func TestSavedReceiverGetsThePasswordOnceVerified(t *testing.T) {
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
	output := startCLIUntil(t, port, credFile, code, "", paired, "-device-id", testReceiverDeviceID)
	if !paired() {
		t.Fatalf("first run saved no pairing:\n%s", output)
	}

	before := server.Stats()
	recorded := func() bool { return server.Stats().RecordRequests > before.RecordRequests }
	output = startCLIUntil(t, port, credFile, code, "", recorded, "-device-id", testReceiverDeviceID)
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
