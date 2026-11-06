package airplay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCredentialStoreSaveRestoreTokenPreservesPairingCredentials(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.Save("device-1", "pair-1", pub1, priv1); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveRestoreToken("device-1", "restore-1"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}

	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.Save("device-1", "pair-2", pub2, priv2); err != nil {
		t.Fatalf("Save second pairing: %v", err)
	}

	creds := store.Lookup("device-1")
	if creds == nil {
		t.Fatal("Lookup returned nil")
	}
	if !creds.HasPairingCredentials() {
		t.Fatal("expected pairing credentials to remain usable")
	}
	if creds.PairingID != "pair-2" {
		t.Fatalf("PairingID = %q, want %q", creds.PairingID, "pair-2")
	}
	if creds.RestoreToken != "restore-1" {
		t.Fatalf("RestoreToken = %q, want %q", creds.RestoreToken, "restore-1")
	}

	gotPub, gotPriv := creds.Ed25519Keys()
	if gotPriv == nil {
		t.Fatal("Ed25519Keys returned nil private key")
	}
	if string(gotPub) != string(pub2) {
		t.Fatal("stored public key did not match latest saved key")
	}
	if string(gotPriv.Seed()) != string(priv2.Seed()) {
		t.Fatal("stored private seed did not match latest saved key")
	}
}

func TestCredentialStoreSaveRestoreTokenCreatesTokenOnlyEntry(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}

	if err := store.SaveRestoreToken("device-2", "restore-only"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}

	creds := store.Lookup("device-2")
	if creds == nil {
		t.Fatal("Lookup returned nil")
	}
	if creds.HasPairingCredentials() {
		t.Fatal("expected token-only entry to have no pairing credentials")
	}
	if creds.RestoreToken != "restore-only" {
		t.Fatalf("RestoreToken = %q, want %q", creds.RestoreToken, "restore-only")
	}
}

func TestCredentialStorePersistsNegotiatedPairingProtocol(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	receiverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	receiver := &ReceiverIdentity{PublicKey: receiverPub}
	if err := store.SavePairing("raw-device", "pair-id", pub, priv, PairingProtocolRaw, receiver, PairingOrigin{}); err != nil {
		t.Fatalf("SavePairing: %v", err)
	}
	if err := store.SaveRestoreToken("raw-device", "restore-token"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}

	reloaded, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("reload credential store: %v", err)
	}
	creds := reloaded.Lookup("raw-device")
	if creds == nil {
		t.Fatal("reloaded credentials are missing")
	}
	if creds.PairingProtocol != PairingProtocolRaw {
		t.Fatalf("reloaded pairing protocol = %q, want %q", creds.PairingProtocol, PairingProtocolRaw)
	}
	if creds.RestoreToken != "restore-token" {
		t.Fatalf("restore token = %q", creds.RestoreToken)
	}

	client := NewAirPlayClient("127.0.0.1", 7000)
	if err := client.RestorePairingCredentials(creds); err != nil {
		t.Fatalf("RestorePairingCredentials: %v", err)
	}
	if got := client.PairingProtocol(); got != PairingProtocolRaw {
		t.Fatalf("restored protocol = %q, want %q", got, PairingProtocolRaw)
	}
}

func TestLegacyCredentialEntryInfersProtocolFromCapabilities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Save is the compatibility API used by releases which predate the protocol
	// field. It deliberately leaves the optional JSON member absent.
	if err := store.Save("old-device", "pair-id", pub, priv); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(data, []byte("pairing_protocol")) {
		t.Fatalf("legacy credential unexpectedly contains pairing_protocol: %s", data)
	}

	reloaded, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("reload credential store: %v", err)
	}
	creds := reloaded.Lookup("old-device")
	if creds == nil {
		t.Fatal("reloaded old-schema credentials are missing")
	}
	if creds.PairingProtocol != PairingProtocolUnknown {
		t.Fatalf("old-schema protocol = %q, want unknown", creds.PairingProtocol)
	}
	for _, test := range []struct {
		name     string
		info     *ReceiverInfo
		protocol PairingProtocol
	}{
		{
			name: "modern HAP capabilities",
			info: &ReceiverInfo{Features: FeatureSystemPairing |
				FeatureTransientPairing | uint64(1<<38)},
			protocol: PairingProtocolHAP,
		},
		{
			name:     "legacy raw capabilities",
			info:     &ReceiverInfo{Features: FeatureLegacyPairing},
			protocol: PairingProtocolRaw,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := NewAirPlayClient("127.0.0.1", 7000)
			client.info = test.info
			if err := client.RestorePairingCredentials(creds); err != nil {
				t.Fatalf("RestorePairingCredentials: %v", err)
			}
			if got := client.PairingProtocol(); got != test.protocol {
				t.Fatalf("restored protocol = %q, want %q", got, test.protocol)
			}
		})
	}
}

func TestRestorePairingCredentialsRejectsUnknownProtocol(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	client := NewAirPlayClient("127.0.0.1", 7000)
	err = client.RestorePairingCredentials(&SavedCredentials{
		PairingID:       "pair-id",
		Ed25519Public:   pub,
		Ed25519Seed:     priv.Seed(),
		PairingProtocol: PairingProtocol("future-protocol"),
	})
	if err == nil {
		t.Fatal("RestorePairingCredentials accepted an unknown protocol")
	}
	if client.PairKeys != nil || client.PairingProtocol() != PairingProtocolUnknown {
		t.Fatal("failed restore partially mutated the client")
	}
}

// How a receiver is paired with again follows the kind of code its pairing
// was made with, so that kind is saved with the pairing, under the field names
// castr copies between its credential files.
func TestSavePairingRecordsTheCodeKindAndWhen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hap := &ReceiverIdentity{ID: "receiver-id", PublicKey: receiverPub}

	readRaw := func(deviceID string) map[string]any {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var file map[string]map[string]any
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		return file[deviceID]
	}
	checkPairedAt := func(entry map[string]any, before time.Time) {
		t.Helper()
		value, _ := entry["paired_at"].(string)
		at, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			t.Fatalf("paired_at = %q: %v", value, err)
		}
		if _, offset := at.Zone(); offset != 0 || !strings.HasSuffix(value, "Z") {
			t.Fatalf("paired_at = %q, want UTC", value)
		}
		if at.Before(before.Add(-time.Second)) || at.After(time.Now().Add(time.Second)) {
			t.Fatalf("paired_at = %v, want about now", at)
		}
	}

	before := time.Now()
	if err := store.SavePairing("pin-device", "pair-id", pub, priv, PairingProtocolHAP, hap,
		PairingOrigin{Code: PairingCodePIN}); err != nil {
		t.Fatal(err)
	}
	entry := readRaw("pin-device")
	if entry["pairing_code"] != "pin" {
		t.Fatalf("pairing_code = %#v, want \"pin\"", entry["pairing_code"])
	}
	checkPairedAt(entry, before)

	// Pairing again replaces both: the kind and time of an earlier pairing say
	// nothing about this one.
	if err := store.SavePairing("pin-device", "pair-id", pub, priv, PairingProtocolHAP, hap,
		PairingOrigin{Code: PairingCodePassword}); err != nil {
		t.Fatal(err)
	}
	if got := store.Lookup("pin-device"); got.PairingCode != PairingCodePassword {
		t.Fatalf("after pairing with a password, pairing_code = %q", got.PairingCode)
	}

	// Raw pair-setup takes no code, whatever the caller claims.
	if err := store.SavePairing("raw-device", "pair-id", pub, priv, PairingProtocolRaw,
		&ReceiverIdentity{PublicKey: receiverPub}, PairingOrigin{Code: PairingCodePIN}); err != nil {
		t.Fatal(err)
	}
	entry = readRaw("raw-device")
	if _, ok := entry["pairing_code"]; ok {
		t.Fatalf("raw pairing saved pairing_code %#v", entry["pairing_code"])
	}
	checkPairedAt(entry, before)

	if err := store.SavePairing("odd-device", "pair-id", pub, priv, PairingProtocolHAP, hap,
		PairingOrigin{Code: "sticky-note"}); err == nil {
		t.Fatal("saved a pairing made with an unknown kind of code")
	}
	if store.Lookup("odd-device") != nil {
		t.Fatal("an unknown kind of code was written")
	}
}

func testPairingKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, *ReceiverIdentity) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, &ReceiverIdentity{ID: "receiver-id", PublicKey: receiverPub}
}

// The address a receiver was paired at names it when nothing else does, so
// only one entry may hold an address: the latest receiver paired there.
func TestSavePairingBindsTheReceiverToItsAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, receiver := testPairingKeys(t)
	save := func(deviceID, address string) {
		t.Helper()
		if err := store.SavePairing(deviceID, "pair-id", pub, priv, PairingProtocolHAP, receiver,
			PairingOrigin{Code: PairingCodePIN, Address: address}); err != nil {
			t.Fatal(err)
		}
	}
	bound := func(address string) string {
		t.Helper()
		deviceID, tied, err := store.ReceiverAtAddress(address)
		if err != nil {
			t.Fatal(err)
		}
		if len(tied) != 0 {
			t.Fatalf("ReceiverAtAddress(%q) tied %v", address, tied)
		}
		return deviceID
	}

	save("AA:AA:AA:AA:AA:01", "Living-Room.local")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"receiver_address": "Living-Room.local"`) {
		t.Fatalf("receiver_address not saved:\n%s", data)
	}
	if got := bound("living-room.LOCAL"); got != "AA:AA:AA:AA:AA:01" {
		t.Fatalf("receiver at the address = %q, want the one paired there", got)
	}
	if got := bound("192.168.1.9"); got != "" {
		t.Fatalf("receiver at an address never paired at = %q", got)
	}

	// A second receiver paired at the same address takes it over.
	save("BB:BB:BB:BB:BB:02", "living-room.local")
	if got := bound("Living-Room.local"); got != "BB:BB:BB:BB:BB:02" {
		t.Fatalf("receiver at the address = %q, want the one paired there last", got)
	}
	if got := store.Lookup("AA:AA:AA:AA:AA:01"); got.ReceiverAddress != "" || !got.HasReceiverIdentity() {
		t.Fatalf("first receiver after losing its address = %+v, want its pairing without the address", got)
	}

	// A pairing saved with no address leaves other entries' addresses alone.
	save("CC:CC:CC:CC:CC:03", "")
	if got := bound("living-room.local"); got != "BB:BB:BB:BB:BB:02" {
		t.Fatalf("receiver at the address = %q after an unrelated pairing", got)
	}
}

// castr copies pairings between its mode files one receiver at a time, so a
// file can hold two entries with the same address. The newest pairing is the
// one at the address; when that cannot be told, neither is.
func TestReceiverAtAddressPrefersTheNewestPairing(t *testing.T) {
	pub, priv, receiver := testPairingKeys(t)
	entry := func(pairedAt string) *SavedCredentials {
		return &SavedCredentials{
			PairingID: "pair-id", Ed25519Public: pub, Ed25519Seed: priv.Seed(),
			PairingProtocol: PairingProtocolHAP, ReceiverID: receiver.ID, ReceiverPublicKey: receiver.PublicKey,
			PairingCode: PairingCodePIN, PairedAt: pairedAt, ReceiverAddress: "192.168.1.5",
		}
	}
	const (
		older = "2026-10-01T10:00:00Z"
		newer = "2026-11-01T10:00:00.5Z"
	)
	for _, test := range []struct {
		name      string
		a, b      string
		want      string
		wantTied  []string
		otherAddr bool
	}{
		{name: "newer wins", a: older, b: newer, want: "BB"},
		{name: "newer wins either way round", a: newer, b: older, want: "AA"},
		{name: "missing counts as oldest", a: "", b: older, want: "BB"},
		{name: "unparsable counts as oldest", a: newer, b: "last tuesday", want: "AA"},
		{name: "tie", a: newer, b: newer, wantTied: []string{"AA", "BB"}},
		{name: "both missing is a tie", a: "", b: "not a time", wantTied: []string{"AA", "BB"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials.json")
			data, err := json.Marshal(map[string]*SavedCredentials{
				"AA": entry(test.a), "BB": entry(test.b),
				"CC": {PairingID: "pair-id", Ed25519Public: pub, Ed25519Seed: priv.Seed(), ReceiverAddress: "192.168.1.6"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := NewCredentialStore(path)
			if err != nil {
				t.Fatal(err)
			}
			got, tied, err := store.ReceiverAtAddress("192.168.1.5")
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want || strings.Join(tied, ",") != strings.Join(test.wantTied, ",") {
				t.Fatalf("ReceiverAtAddress = (%q, %v), want (%q, %v)", got, tied, test.want, test.wantTied)
			}
		})
	}
}

// A backend that cannot list its entries cannot say who was paired where.
func TestReceiverAtAddressWithoutAListableBackend(t *testing.T) {
	store := NewCredentialStoreWithBackend(lookupOnlyBackend{})
	if got, tied, err := store.ReceiverAtAddress("192.168.1.5"); got != "" || tied != nil || err != nil {
		t.Fatalf("ReceiverAtAddress = (%q, %v, %v), want no binding", got, tied, err)
	}
}

type lookupOnlyBackend struct{}

func (lookupOnlyBackend) Lookup(string) (*SavedCredentials, error) { return nil, nil }
func (lookupOnlyBackend) Save(string, *SavedCredentials) error     { return nil }
