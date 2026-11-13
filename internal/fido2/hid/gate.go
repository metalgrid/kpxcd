//go:build linux

package hid

import (
	"context"
)

// OperationKind distinguishes what a gate approval covers.
type OperationKind string

const (
	// OperationRegister approves credential creation for an RPID.
	OperationRegister OperationKind = "register"
	// OperationAuthenticate approves an assertion for an RPID.
	OperationAuthenticate OperationKind = "authenticate"
)

// Operation is one user-presence request presented to the Gate.
type Operation struct {
	Kind OperationKind
	RPID string
}

// Gate answers user-presence requests. Denial is the zero behavior: a nil
// Gate denies every operation, and a Gate that errors denies. There is no
// allow-by-default anywhere in this package.
type Gate interface {
	// Approve blocks until the human decides or the deadline passes.
	// It must honor ctx cancellation (returning false on cancel).
	Approve(ctx context.Context, op Operation) bool
}

// denyAllGate is the zero gate: every operation is denied.
type denyAllGate struct{}

func (denyAllGate) Approve(context.Context, Operation) bool {
	return false
}

// CredentialStore is the persisted-credential surface the CTAP commands
// drive. Implementations enforce RP binding and persistence themselves;
// by the time the store is called, the gate has already approved.
type CredentialStore interface {
	// Create registers a new passkey for the RPID and returns the
	// credential ID, user handle, and COSE-encoded public key.
	Create(rpID, rpName, userName, userDisplayName string) (credentialID, userHandle, coseKey []byte, err error)

	// Assert signs for the credential matching rpID and credentialID
	// (nil credentialID selects the newest resident credential for the
	// RPID). Returns the credential ID actually used — resident lookups
	// must surface it — plus user handle, authenticator data, and
	// signature. The store refuses unknown or cross-RP credentials and
	// returns ErrNoCredentials when nothing matches.
	Assert(rpID string, credentialID, clientDataHash []byte, userVerified bool) (usedCredentialID, userHandle, authenticatorData, signature []byte, err error)

	// HasCredentialsForRPID reports whether any resident credential
	// exists for the RPID. GetAssertion consults this before asking the
	// gate so sites with no credentials never trigger a prompt.
	HasCredentialsForRPID(rpID string) (bool, error)
}
