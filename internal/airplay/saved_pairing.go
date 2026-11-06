package airplay

import (
	"context"
	"errors"
	"fmt"
)

// SavedPairingStep is what to do next with a receiver this machine holds a
// saved pairing for.
type SavedPairingStep int

const (
	// SavedPairingVerified: the receiver proved it is the one paired with.
	SavedPairingVerified SavedPairingStep = iota
	// SavedPairingPairWithCode: pair again with a PIN or password, through
	// PairWithCode -- never Pair, which goes transient when /info says so.
	// Only the real receiver can show its PIN on its own screen, so this
	// cannot hand the stream to an impersonator.
	SavedPairingPairWithCode
	// SavedPairingPairAsNew: pair as with a receiver never seen before. Only
	// for a raw pairing saved before receiver identities were recorded: raw
	// pair-setup takes no code, so pairing again is no weaker than the first
	// time was.
	SavedPairingPairAsNew
	// SavedPairingRefuse: do not cast, and do not pair in any other way.
	SavedPairingRefuse
)

// AfterSavedPairing decides what follows a saved pairing, calling verify --
// restore the pairing and run pair-verify -- only when there is a receiver
// identity to verify against.
//
// The rule it exists to keep: once this machine has paired with a receiver,
// nothing falls back to transient pairing for it. Transient pairing
// authenticates nobody, and whether a receiver "needs no code" is read from
// /info, which the device at the address writes itself. Falling back after a
// failed verify -- as the callers used to -- let an impersonator fail on
// purpose, claim to need no code, and receive the stream.
func AfterSavedPairing(saved *SavedCredentials, verify func() error) SavedPairingStep {
	raw := saved.UsesRawPairing()
	if !saved.HasReceiverIdentity() {
		// Nothing to authenticate it against; pair again to record one.
		if raw {
			return SavedPairingPairAsNew
		}
		return SavedPairingPairWithCode
	}
	err := verify()
	switch {
	case err == nil:
		return SavedPairingVerified
	case errors.Is(err, ErrReceiverNotAuthenticated):
		// The device answering is not the paired receiver, or will not prove
		// it. No other mode may stand in for that proof.
		return SavedPairingRefuse
	case raw:
		// A raw receiver cannot be paired with again any more securely than
		// by trusting whatever answers, so its saved pairing is not replaced
		// behind the user's back.
		return SavedPairingRefuse
	default:
		// The receiver answered as itself but would not accept this machine
		// -- typically it has forgotten it.
		return SavedPairingPairWithCode
	}
}

// ErrPasswordPairingNotRepeated means a saved pairing was made with the
// receiver's pairing password and must be made again, which only the user
// may ask for.
var ErrPasswordPairingNotRepeated = errors.New("the saved pairing was made with the receiver's pairing password, which is not sent again unless asked")

// CodePrompts asks the user for the code to pair again with.
type CodePrompts struct {
	// PIN returns the PIN the user reads off the receiver, which has just
	// been asked to show one.
	PIN func() (string, error)
	// Password returns the receiver's pairing password when none was preset.
	Password func() (string, error)
}

// PairAgainWithCode pairs again, through PairWithCode, with a receiver this
// machine holds the saved pairing saved for, and returns the kind of code it
// used, for SavePairing.
//
// The kind is the one the pairing was made with, never what /info says now:
// /info is written by whatever answers at the address, and a device claiming
// to be a legacy pairing-password receiver would otherwise be handed the
// preset code -- or a Digest of it -- without showing anything.
//
//   - A PIN pairing, or one saved before the kind was recorded, shows a PIN on
//     the receiver and uses only the code typed for it. Only the real receiver
//     can show its PIN on its own screen. The preset code is not used, and
//     no Digest password is installed on the client for the exchange.
//   - A pairing-password pairing is made again only when explicit (the user
//     asked to pair); otherwise ErrPasswordPairingNotRepeated.
func (c *AirPlayClient) PairAgainWithCode(ctx context.Context, saved *SavedCredentials, explicit bool, presetPassword string, prompts CodePrompts) (PairingCode, error) {
	if saved != nil && saved.PairingCode == PairingCodePassword {
		if !explicit {
			return PairingCodeNone, ErrPasswordPairingNotRepeated
		}
		code := presetPassword
		if code == "" {
			if prompts.Password == nil {
				return PairingCodeNone, fmt.Errorf("pairing again needs the receiver's pairing password")
			}
			var err error
			if code, err = prompts.Password(); err != nil {
				return PairingCodeNone, err
			}
		}
		// A legacy password receiver takes the same password for Digest.
		c.SetPassword(code)
		if err := c.PairWithCode(ctx, code); err != nil {
			return PairingCodeNone, err
		}
		return PairingCodePassword, nil
	}

	c.SetPassword("")
	if err := c.StartPINDisplay(); err != nil {
		return PairingCodeNone, fmt.Errorf("the receiver will not show a PIN to pair again with (%v); "+
			"if this receiver uses a pairing password rather than an on-screen code, "+
			"remove its entry from the credentials file and connect again", err)
	}
	code, err := prompts.PIN()
	if err != nil {
		return PairingCodeNone, err
	}
	if err := c.PairWithCode(ctx, code); err != nil {
		return PairingCodeNone, err
	}
	return PairingCodePIN, nil
}
