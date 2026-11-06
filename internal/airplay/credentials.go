package airplay

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SavedCredentials holds the persistent pairing credentials and optional
// screencast restore state for a single device.
type SavedCredentials struct {
	PairingID       string          `json:"pairing_id"`
	Ed25519Public   []byte          `json:"ed25519_public"`
	Ed25519Seed     []byte          `json:"ed25519_seed"` // 32-byte seed (private key is derived from this)
	PairingProtocol PairingProtocol `json:"pairing_protocol,omitempty"`
	// ReceiverID and ReceiverPublicKey are the RECEIVER's long-term identity,
	// proven during pair-setup: its HAP pairing identifier (empty for raw
	// pairings) and Ed25519 public key. Every later pair-verify checks the
	// receiver's signature against them. Credentials saved before they were
	// recorded cannot tell the paired receiver from an impersonator, and are
	// not used to verify -- the receiver is paired with again instead.
	ReceiverID        string `json:"receiver_id,omitempty"`
	ReceiverPublicKey []byte `json:"receiver_ed25519_public,omitempty"`
	// PairedAt is when the pairing was made, in RFC 3339 UTC.
	PairedAt string `json:"paired_at,omitempty"`
	// PairingCode is the kind of code the pairing was made with. Pairing again
	// follows it rather than /info, which whatever answers at the address
	// writes: an impersonator claiming a pairing password would otherwise be
	// handed the preset code, or a Digest of it, without showing any PIN.
	// Raw pairings, made with no code, leave it empty.
	PairingCode PairingCode `json:"pairing_code,omitempty"`
	// ReceiverAddress is the host this machine was told to connect to when
	// it made the pairing. Reaching a receiver by address alone, the device
	// there is otherwise taken at its word about which receiver it is; the
	// address names the receiver meant instead. Only one entry in a store
	// holds a given address.
	ReceiverAddress string `json:"receiver_address,omitempty"`
	RestoreToken    string `json:"restore_token,omitempty"`
}

// PairingCode is the kind of code a pairing was made with.
type PairingCode string

const (
	PairingCodeNone PairingCode = ""
	// PairingCodePIN is a code shown afresh on the receiver's screen.
	PairingCodePIN PairingCode = "pin"
	// PairingCodePassword is a pairing password configured on the receiver.
	PairingCodePassword PairingCode = "password"
)

// PairingOrigin is how a pairing being saved was made.
type PairingOrigin struct {
	// Code is the kind of code pair-setup was given.
	Code PairingCode
	// Address is the host connected to, which the pairing takes over from
	// any other entry. Empty leaves addresses as they are.
	Address string
}

// PairingProtocol is the pair-verify wire protocol negotiated when credentials
// were created. It must be restored before reusing the keys: HAP pair-verify
// enables encrypted control framing, while raw AirPlay pair-verify does not.
type PairingProtocol string

const (
	PairingProtocolUnknown PairingProtocol = ""
	PairingProtocolHAP     PairingProtocol = "hap"
	PairingProtocolRaw     PairingProtocol = "raw"
)

// DefaultCredentialsPath returns ~/.config/doubletake/credentials.json.
func DefaultCredentialsPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "doubletake", "credentials.json")
}

// Ed25519Keys reconstructs the key pair from saved credentials.
func (c *SavedCredentials) Ed25519Keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(c.Ed25519Seed) != ed25519.SeedSize {
		return nil, nil
	}
	priv := ed25519.NewKeyFromSeed(c.Ed25519Seed)
	return ed25519.PublicKey(c.Ed25519Public), priv
}

// HasPairingCredentials reports whether the saved entry contains a usable
// AirPlay pairing identity.
func (c *SavedCredentials) HasPairingCredentials() bool {
	return c != nil && c.PairingID != "" &&
		len(c.Ed25519Public) == ed25519.PublicKeySize &&
		len(c.Ed25519Seed) == ed25519.SeedSize
}

// HasReceiverIdentity reports whether the saved entry records the receiver's
// own identity, which pair-verify needs to authenticate it.
func (c *SavedCredentials) HasReceiverIdentity() bool {
	if c == nil || len(c.ReceiverPublicKey) != ed25519.PublicKeySize {
		return false
	}
	// A HAP pairing names its receiver; a raw one has no identifier to name.
	return c.ReceiverID != "" || c.PairingProtocol == PairingProtocolRaw
}

// UsesRawPairing reports whether the saved pairing is a raw AirPlay pairing.
// Raw pair-setup takes no code and authenticates nobody; the only identity
// such a pairing can hold is the key the receiver gave the first time.
//
// Only the entry itself can say so. Entries older than PairingProtocol name no
// protocol; RestorePairingCredentials guesses theirs from /info, but /info is
// written by whatever answers at the address, and treating such an entry as
// raw would let that device choose to be paired with without a code. They
// count as code-paired.
func (c *SavedCredentials) UsesRawPairing() bool {
	return c != nil && c.PairingProtocol == PairingProtocolRaw
}

// RestorePairingCredentials installs a saved identity and its negotiated wire
// protocol on the client. Call this before PairVerify.
func (c *AirPlayClient) RestorePairingCredentials(saved *SavedCredentials) error {
	if saved == nil || !saved.HasPairingCredentials() {
		return fmt.Errorf("saved credentials contain no usable pairing identity")
	}
	protocol := saved.PairingProtocol
	if protocol == PairingProtocolUnknown {
		// Old credential files predate explicit protocol persistence. Preserve the
		// previous capability-driven behavior: legacy pairing profiles used raw
		// pair-verify, while CoreUtils/HAP profiles used encrypted verification.
		protocol = PairingProtocolHAP
		if c.info != nil && c.info.PrefersLegacyPairing() {
			protocol = PairingProtocolRaw
		}
	}
	switch protocol {
	case PairingProtocolHAP:
		c.pairingProtocol = pairingProtocolHAP
	case PairingProtocolRaw:
		c.pairingProtocol = pairingProtocolRaw
	default:
		return fmt.Errorf("saved credentials contain unknown pairing protocol %q", protocol)
	}

	pub, priv := saved.Ed25519Keys()
	c.PairingID = saved.PairingID
	c.PairKeys = &PairKeys{
		Ed25519Public:  append(ed25519.PublicKey(nil), pub...),
		Ed25519Private: append(ed25519.PrivateKey(nil), priv...),
	}
	// Restored only when present. Without it PairVerify refuses rather than
	// accept whatever answers, and the caller pairs again to record it.
	c.receiver = nil
	c.transientSetup = false
	if saved.HasReceiverIdentity() {
		c.receiver = &ReceiverIdentity{
			ID:        saved.ReceiverID,
			PublicKey: append(ed25519.PublicKey(nil), saved.ReceiverPublicKey...),
		}
	}
	return nil
}

// CredentialBackend is the storage interface for pairing credentials.
type CredentialBackend interface {
	Lookup(deviceID string) (*SavedCredentials, error)
	Save(deviceID string, creds *SavedCredentials) error
}

// listingBackend is a CredentialBackend that can also list its entries,
// which binding receivers to addresses needs.
type listingBackend interface {
	CredentialBackend
	All() (map[string]*SavedCredentials, error)
}

// CredentialStore manages per-device pairing credentials using a pluggable backend.
type CredentialStore struct {
	mu      sync.Mutex
	backend CredentialBackend
}

// NewCredentialStore creates a credential store backed by a JSON file at path.
func NewCredentialStore(path string) (*CredentialStore, error) {
	fb, err := newFileBackend(path)
	if err != nil {
		return nil, err
	}
	return &CredentialStore{backend: fb}, nil
}

// NewCredentialStoreWithBackend creates a credential store with the given backend.
func NewCredentialStoreWithBackend(b CredentialBackend) *CredentialStore {
	return &CredentialStore{backend: b}
}

// Lookup returns saved credentials for a device, or nil if not found.
func (cs *CredentialStore) Lookup(deviceID string) *SavedCredentials {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	creds, err := cs.backend.Lookup(deviceID)
	if err != nil {
		return nil
	}
	return creds
}

// LookupReceiver finds the saved pairing for a receiver, given the device ID
// the caller means (expectedID, from discovery or configuration; may be empty)
// and the one the device at the address reports in /info (reportedID).
//
// The reported ID alone cannot be trusted: the device writes it itself. An
// impersonator that names itself as a receiver never seen before has no saved
// pairing to fail, and would be paired with from scratch -- transiently, if it
// also claims to need no code. So when the caller knows which receiver it
// means, that receiver's pairing is the one that applies, and a device naming
// itself differently is refused while that pairing exists.
//
// A store that cannot be read is an error, not "never paired": treating a
// locked keyring as a first contact would pair from scratch with whatever
// answers.
func (cs *CredentialStore) LookupReceiver(expectedID, reportedID string) (*SavedCredentials, error) {
	if expectedID == "" || strings.EqualFold(expectedID, reportedID) {
		saved, err := cs.lookup(reportedID)
		if err != nil || saved != nil || expectedID == "" {
			return saved, err
		}
		return cs.lookup(expectedID)
	}
	saved, err := cs.lookup(expectedID)
	if err != nil {
		return nil, err
	}
	if saved.HasPairingCredentials() {
		return nil, fmt.Errorf("%w: the device at this address names itself %q, not %q, which this machine "+
			"paired with (if %q has left and another receiver now has its address, discover again)",
			ErrReceiverNotAuthenticated, reportedID, expectedID, expectedID)
	}
	// Not paired with the receiver meant, so this is a first contact either
	// way; the device's own ID is what its pairing will be saved under.
	return cs.lookup(reportedID)
}

func (cs *CredentialStore) lookup(deviceID string) (*SavedCredentials, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	creds, err := cs.backend.Lookup(deviceID)
	if err != nil {
		return nil, fmt.Errorf("read saved pairing for %s: %w", deviceID, err)
	}
	return creds, nil
}

// ReceiverAtAddress returns the device ID of the receiver this machine last
// paired with at address (a host, compared case-insensitively), or "" if
// none. A receiver reached only by address can then be held to the one paired
// there, rather than to whatever the device at the address says it is.
//
// SavePairing keeps one entry per address, but castr copies pairings between
// its credential files one receiver at a time, so a file can hold several.
// The newest paired_at wins; an entry whose paired_at is missing or
// unparsable counts as oldest. When the newest cannot be told apart, nothing
// is returned and tied names them, so the caller can say so.
//
// A backend that cannot list its entries binds nothing.
func (cs *CredentialStore) ReceiverAtAddress(address string) (deviceID string, tied []string, err error) {
	if address == "" {
		return "", nil, nil
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	lister, ok := cs.backend.(listingBackend)
	if !ok {
		return "", nil, nil
	}
	entries, err := lister.All()
	if err != nil {
		return "", nil, fmt.Errorf("read saved pairings: %w", err)
	}
	var newest time.Time
	for id, creds := range entries {
		if !creds.HasPairingCredentials() || !strings.EqualFold(creds.ReceiverAddress, address) {
			continue
		}
		pairedAt, _ := time.Parse(time.RFC3339Nano, creds.PairedAt)
		switch {
		case (deviceID == "" && tied == nil) || pairedAt.After(newest):
			deviceID, tied, newest = id, nil, pairedAt
		case pairedAt.Equal(newest):
			if deviceID != "" {
				tied = append(tied, deviceID)
				deviceID = ""
			}
			tied = append(tied, id)
		}
	}
	sort.Strings(tied)
	return deviceID, tied, nil
}

// Len returns the number of stored credential entries.
// Only supported by the file backend; returns 0 for other backends.
func (cs *CredentialStore) Len() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if fb, ok := cs.backend.(*fileBackend); ok {
		return len(fb.devices)
	}
	return 0
}

// Save stores credentials for a device.
func (cs *CredentialStore) Save(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	return cs.savePairing(deviceID, pairingID, pub, priv, PairingProtocolUnknown)
}

// SavePairing stores credentials together with the protocol which actually
// completed and the receiver identity that pair-setup proved. New production
// call sites should use this instead of Save.
//
// A pairing is refused without the receiver's identity: saving one would
// produce credentials that cannot authenticate the receiver they were made
// with, which is the weakness this field exists to close.
//
// origin records the kind of code used, which decides how the receiver is
// paired with again; see SavedCredentials.PairingCode.
func (cs *CredentialStore) SavePairing(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, protocol PairingProtocol, receiver *ReceiverIdentity, origin PairingOrigin) error {
	if protocol != PairingProtocolHAP && protocol != PairingProtocolRaw {
		return fmt.Errorf("cannot save unknown pairing protocol %q", protocol)
	}
	if !receiver.valid() || (protocol == PairingProtocolHAP && receiver.ID == "") {
		return fmt.Errorf("cannot save a pairing without the receiver's proven identity")
	}
	switch origin.Code {
	case PairingCodeNone, PairingCodePIN, PairingCodePassword:
	default:
		return fmt.Errorf("cannot save unknown pairing code kind %q", origin.Code)
	}
	if protocol == PairingProtocolRaw {
		// Raw pair-setup takes no code, whatever the caller offered.
		origin.Code = PairingCodeNone
	}
	return cs.savePairingWith(deviceID, pairingID, pub, priv, protocol, receiver, origin, time.Now().UTC())
}

func (cs *CredentialStore) savePairing(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, protocol PairingProtocol) error {
	return cs.savePairingWith(deviceID, pairingID, pub, priv, protocol, nil, PairingOrigin{}, time.Time{})
}

func (cs *CredentialStore) savePairingWith(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, protocol PairingProtocol, receiver *ReceiverIdentity, origin PairingOrigin, pairedAt time.Time) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	creds, err := cs.backend.Lookup(deviceID)
	if err != nil {
		return err
	}
	if creds == nil {
		creds = &SavedCredentials{}
	}
	if origin.Address != "" {
		// The address now names this receiver, and no other.
		if err := cs.releaseAddressLocked(origin.Address, deviceID); err != nil {
			return err
		}
		creds.ReceiverAddress = origin.Address
	}
	creds.PairingID = pairingID
	creds.Ed25519Public = append([]byte(nil), pub...)
	creds.Ed25519Seed = append([]byte(nil), priv.Seed()...)
	if protocol != PairingProtocolUnknown {
		creds.PairingProtocol = protocol
	}
	// Written together with the keys, never left behind from an older
	// pairing: a new key beside a previous receiver's identity would describe
	// a pairing that never happened.
	creds.ReceiverID, creds.ReceiverPublicKey = "", nil
	if receiver.valid() {
		creds.ReceiverID = receiver.ID
		creds.ReceiverPublicKey = append([]byte(nil), receiver.PublicKey...)
	}
	// Likewise: how and when an earlier pairing was made says nothing about
	// this one.
	creds.PairingCode = origin.Code
	creds.PairedAt = ""
	if !pairedAt.IsZero() {
		creds.PairedAt = pairedAt.Format(time.RFC3339Nano)
	}
	return cs.backend.Save(deviceID, creds)
}

// releaseAddressLocked removes address from every entry but keepID's.
func (cs *CredentialStore) releaseAddressLocked(address, keepID string) error {
	lister, ok := cs.backend.(listingBackend)
	if !ok {
		return nil
	}
	entries, err := lister.All()
	if err != nil {
		return fmt.Errorf("read saved pairings: %w", err)
	}
	for id, creds := range entries {
		if id == keepID || !strings.EqualFold(creds.ReceiverAddress, address) {
			continue
		}
		creds.ReceiverAddress = ""
		if err := cs.backend.Save(id, creds); err != nil {
			return err
		}
	}
	return nil
}

// SaveRestoreToken stores a Wayland screencast restore token for a device.
func (cs *CredentialStore) SaveRestoreToken(deviceID, restoreToken string) error {
	if restoreToken == "" {
		return nil
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	creds, err := cs.backend.Lookup(deviceID)
	if err != nil {
		return err
	}
	if creds == nil {
		creds = &SavedCredentials{}
	}
	creds.RestoreToken = restoreToken
	return cs.backend.Save(deviceID, creds)
}

// fileBackend stores credentials as a JSON file on disk.
type fileBackend struct {
	path    string
	devices map[string]*SavedCredentials
}

func newFileBackend(path string) (*fileBackend, error) {
	fb := &fileBackend{
		path:    path,
		devices: make(map[string]*SavedCredentials),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fb, nil
		}
		return nil, fmt.Errorf("read credential store: %w", err)
	}
	if err := json.Unmarshal(data, &fb.devices); err != nil {
		return nil, fmt.Errorf("unmarshal credential store: %w", err)
	}
	return fb, nil
}

func (fb *fileBackend) Lookup(deviceID string) (*SavedCredentials, error) {
	return fb.devices[deviceID], nil
}

func (fb *fileBackend) All() (map[string]*SavedCredentials, error) {
	return fb.devices, nil
}

func (fb *fileBackend) Save(deviceID string, creds *SavedCredentials) error {
	fb.devices[deviceID] = creds
	return fb.persist()
}

func (fb *fileBackend) persist() error {
	dir := filepath.Dir(fb.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create credential dir: %w", err)
	}
	data, err := json.MarshalIndent(fb.devices, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credential store: %w", err)
	}
	if err := os.WriteFile(fb.path, data, 0600); err != nil {
		return fmt.Errorf("write credential store: %w", err)
	}
	return nil
}
