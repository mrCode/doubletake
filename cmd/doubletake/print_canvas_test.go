package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

// featureScreenMultiCodec is AirPlay feature 42, which gates HEVC.
const featureScreenMultiCodec = uint64(1) << 42

// displayInfoResponse is /info from a receiver with one display of the given
// nominal and maximum size.
func displayInfoResponse(t *testing.T, features uint64, width, height, maxWidth, maxHeight int) scriptedResponse {
	t.Helper()
	info := map[string]any{
		"name":     "Living Room",
		"model":    "AppleTV-Test",
		"deviceID": testReceiverDeviceID,
		"features": features,
	}
	if width > 0 && height > 0 {
		info["displays"] = []map[string]any{{
			"widthPixels": width, "heightPixels": height,
			"widthPixelsMax": maxWidth, "heightPixelsMax": maxHeight,
		}}
	}
	body, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("encode /info: %v", err)
	}
	return scriptedResponse{status: 200, headers: map[string]string{"Content-Type": "application/x-apple-binary-plist"}, body: body}
}

type printCanvasRun struct {
	stdout, stderr string
	exitCode       int
}

// runPrintCanvas runs doubletake -print-canvas against port with args,
// keeping stdout apart from the log so its one line can be checked exactly.
func runPrintCanvas(t *testing.T, credFile, code string, args ...string) printCanvasRun {
	t.Helper()
	all := append([]string{"-print-canvas", "-creds", credFile}, args...)
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
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("doubletake -print-canvas did not finish: %s%s", stdout.String(), stderr.String())
	}
	run := printCanvasRun{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		run.exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run doubletake -print-canvas: %v", err)
	}
	return run
}

func requireCanvas(t *testing.T, run printCanvasRun, want string) {
	t.Helper()
	if run.exitCode != 0 || run.stdout != "canvas "+want+"\n" {
		t.Fatalf("-print-canvas = exit %d stdout %q, want exit 0 stdout %q\nstderr:\n%s", run.exitCode, run.stdout, "canvas "+want+"\n", run.stderr)
	}
}

func requireCanvasUnknown(t *testing.T, run printCanvasRun, reason string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(run.stdout, "\n"), "\n")
	if run.exitCode != 1 || len(lines) != 1 || !strings.HasPrefix(lines[0], "canvas unknown: ") || !strings.Contains(lines[0], reason) {
		t.Fatalf("-print-canvas = exit %d stdout %q, want exit 1 and one line \"canvas unknown: ...%s...\"\nstderr:\n%s", run.exitCode, run.stdout, reason, run.stderr)
	}
}

func missingCredentials(t *testing.T) string {
	return filepath.Join(t.TempDir(), "credentials.json")
}

func TestPrintCanvasReportsTheNominalCanvasForH264(t *testing.T) {
	receiver := startScriptedReceiver(t, func(scriptedRequest) scriptedResponse {
		return displayInfoResponse(t, modernTestFeatures|featureScreenMultiCodec, 1920, 1080, 3840, 2160)
	})
	for _, codec := range []string{"h264", "auto"} {
		t.Run(codec, func(t *testing.T) {
			run := runPrintCanvas(t, missingCredentials(t), "", "-target", "127.0.0.1", "-port", receiver.port(), "-video-codec", codec)
			requireCanvas(t, run, "1920x1080")
		})
	}
	t.Run("default codec", func(t *testing.T) {
		run := runPrintCanvas(t, missingCredentials(t), "", "-target", "127.0.0.1", "-port", receiver.port())
		requireCanvas(t, run, "1920x1080")
	})
}

func TestPrintCanvasReportsTheCappedMaximumForHEVC(t *testing.T) {
	receiver := startScriptedReceiver(t, func(scriptedRequest) scriptedResponse {
		return displayInfoResponse(t, modernTestFeatures|featureScreenMultiCodec, 1920, 1080, 3840, 2160)
	})
	run := runPrintCanvas(t, missingCredentials(t), "", "-target", "127.0.0.1", "-port", receiver.port(), "-video-codec", "hevc")
	requireCanvas(t, run, "3840x2160")
	run = runPrintCanvas(t, missingCredentials(t), "", "-target", "127.0.0.1", "-port", receiver.port(), "-video-codec", "hevc", "-max-size", "2560x1440")
	requireCanvas(t, run, "2560x1440")
}

func TestPrintCanvasNeverPairsOrTouchesCredentials(t *testing.T) {
	receiver := startScriptedReceiver(t, func(scriptedRequest) scriptedResponse {
		return displayInfoResponse(t, legacyTestFeatures|featureScreenMultiCodec, 1920, 1080, 3840, 2160)
	})
	// A credentials file that cannot be parsed: reading it at all fails the
	// run, and any write would change it.
	credFile := filepath.Join(t.TempDir(), "credentials.json")
	garbage := []byte("not credentials")
	if err := os.WriteFile(credFile, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	run := runPrintCanvas(t, credFile, presetCode, "-target", "127.0.0.1", "-port", receiver.port(), "-pair")
	requireCanvas(t, run, "1920x1080")

	requests := receiver.seen()
	if len(requests) != 1 || requests[0].method != "GET" || requests[0].path != "/info" {
		paths := make([]string, 0, len(requests))
		for _, request := range requests {
			paths = append(paths, request.method+" "+request.path)
		}
		t.Fatalf("receiver saw %q, want only GET /info", paths)
	}
	requireNoAuthorization(t, requests)
	if after, err := os.ReadFile(credFile); err != nil || !bytes.Equal(after, garbage) {
		t.Fatalf("credentials file after -print-canvas = %q err=%v, want it untouched", after, err)
	}
	entries, err := os.ReadDir(filepath.Dir(credFile))
	if err != nil || len(entries) != 1 {
		t.Fatalf("credentials directory holds %d entries err=%v, want only the original file", len(entries), err)
	}
}

func TestPrintCanvasSaysUnknownWhenItCannotTell(t *testing.T) {
	withoutHEVC := startScriptedReceiver(t, func(scriptedRequest) scriptedResponse {
		return displayInfoResponse(t, modernTestFeatures, 1920, 1080, 3840, 2160)
	})
	noDisplay := startScriptedReceiver(t, func(scriptedRequest) scriptedResponse {
		return displayInfoResponse(t, modernTestFeatures|featureScreenMultiCodec, 0, 0, 0, 0)
	})
	refusing := startScriptedReceiver(t, func(scriptedRequest) scriptedResponse {
		// The body is the device's to choose; it must not add lines to stdout.
		return scriptedResponse{status: 403, body: []byte("go\naway\r\ncanvas 3840x2160")}
	})
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := strconv.Itoa(closed.Addr().(*net.TCPAddr).Port)
	_ = closed.Close()

	for _, test := range []struct {
		name   string
		args   []string
		reason string
	}{
		{name: "HEVC without feature 42", args: []string{"-target", "127.0.0.1", "-port", withoutHEVC.port(), "-video-codec", "hevc"}, reason: "feature 42"},
		{name: "no display advertised", args: []string{"-target", "127.0.0.1", "-port", noDisplay.port()}, reason: "no display"},
		{name: "info refused", args: []string{"-target", "127.0.0.1", "-port", refusing.port()}, reason: "403"},
		{name: "nothing listening", args: []string{"-target", "127.0.0.1", "-port", closedPort}, reason: "connect"},
		{name: "no target", args: nil, reason: "-target"},
		{name: "malformed max size", args: []string{"-target", "127.0.0.1", "-port", noDisplay.port(), "-max-size", "big"}, reason: "-max-size must be WIDTHxHEIGHT"},
		{name: "unknown codec", args: []string{"-target", "127.0.0.1", "-port", noDisplay.port(), "-video-codec", "vp9"}, reason: "vp9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requireCanvasUnknown(t, runPrintCanvas(t, missingCredentials(t), "", test.args...), test.reason)
		})
	}
}
