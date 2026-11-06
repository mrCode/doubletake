package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAfterSavedPairingNeverFallsBackToTransient(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	receiverKey := ed25519.NewKeyFromSeed(pinSetupReceiverSeed).Public().(ed25519.PublicKey)
	saved := func(protocol PairingProtocol, withIdentity bool) *SavedCredentials {
		c := &SavedCredentials{
			PairingID:       "pair-id",
			Ed25519Public:   key.Public().(ed25519.PublicKey),
			Ed25519Seed:     key.Seed(),
			PairingProtocol: protocol,
		}
		if withIdentity {
			c.ReceiverPublicKey = receiverKey
			if protocol == PairingProtocolHAP {
				c.ReceiverID = pinSetupReceiverID
			}
		}
		return c
	}
	notAuthenticated := fmt.Errorf("wrapped: %w", ErrReceiverNotAuthenticated)
	forgotten := errors.New("pair-verify V4 error: 2")

	for _, test := range []struct {
		name         string
		saved        *SavedCredentials
		verifyErr    error
		want         SavedPairingStep
		wantVerified bool
	}{
		{"HAP, receiver proves itself", saved(PairingProtocolHAP, true), nil, SavedPairingVerified, true},
		{"HAP, impostor", saved(PairingProtocolHAP, true), notAuthenticated, SavedPairingRefuse, true},
		{"HAP, receiver forgot this machine", saved(PairingProtocolHAP, true), forgotten, SavedPairingPairWithCode, true},
		{"HAP saved before identities", saved(PairingProtocolHAP, false), nil, SavedPairingPairWithCode, false},
		{"raw, receiver proves itself", saved(PairingProtocolRaw, true), nil, SavedPairingVerified, true},
		{"raw, impostor", saved(PairingProtocolRaw, true), notAuthenticated, SavedPairingRefuse, true},
		{"raw, other failure", saved(PairingProtocolRaw, true), forgotten, SavedPairingRefuse, true},
		{"raw saved before identities", saved(PairingProtocolRaw, false), nil, SavedPairingPairAsNew, false},
		// Older than pairing_protocol: /info would decide whether it is raw,
		// and /info is the impersonator's. It counts as code-paired.
		{"no protocol recorded", saved(PairingProtocolUnknown, false), nil, SavedPairingPairWithCode, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			verified := false
			got := AfterSavedPairing(test.saved, func() error {
				verified = true
				return test.verifyErr
			})
			if got != test.want {
				t.Errorf("step = %d, want %d", got, test.want)
			}
			if verified != test.wantVerified {
				t.Errorf("verify called = %t, want %t", verified, test.wantVerified)
			}
		})
	}
}

// Raw pairing takes no code, so pairing again raw sends no Digest of the
// preset code, even with one installed on the client.
func TestPairAgainRawSendsNoCode(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))
	client := NewAirPlayClient("127.0.0.1", 7000)
	client.conn = clientConn
	client.info = &ReceiverInfo{}
	client.SetPassword("preset-code")

	served := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		for {
			request, err := readRTSPTestRequest(reader)
			if err != nil {
				served <- nil
				return
			}
			if auth := request.headers["authorization"]; auth != "" {
				served <- fmt.Errorf("%s %s carried Authorization %q", request.method, request.uri, auth)
				return
			}
			if request.uri == "/pair-setup" && len(request.body) != 32 {
				served <- fmt.Errorf("pair-setup body is %d bytes, not raw pair-setup", len(request.body))
				return
			}
			if err := writeRTSPTestResponse(serverConn, 401, map[string]string{
				"WWW-Authenticate": `Digest realm="airplay", nonce="impostor-nonce"`,
			}, nil); err != nil {
				served <- err
				return
			}
		}
	}()

	err := client.PairAgainRaw(context.Background())
	if err == nil || !strings.Contains(err.Error(), "remove its entry from the credentials file") {
		t.Fatalf("PairAgainRaw against a challenging device = %v, want a refusal with advice", err)
	}
	clientConn.Close()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}
