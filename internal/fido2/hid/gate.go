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

// Operation identifies the checks the gate must establish for this request.
// Results separately report the checks actually established by the gate.
type Operation struct {
	Kind             OperationKind
	RPID             string
	UserPresence     bool
	UserVerification bool
}

// Approval separates the decision from the checks actually established.
// The zero result denies; properties on a denied result are never used.
type Approval struct {
	Approved         bool
	UserPresence     bool
	UserVerification bool
}

// Gate reports actual checks, including any additional checks established.
// Callers require approval and every requested property before using a result.
type Gate interface {
	// Approve blocks until the human decides or the deadline passes.
	// It must honor ctx cancellation (returning a zero Approval on cancel).
	Approve(ctx context.Context, op Operation) Approval
}

// denyAllGate is the zero gate: every operation is denied.
type denyAllGate struct{}

func (denyAllGate) Approve(context.Context, Operation) Approval {
	return Approval{}
}

// CredentialReference identifies an exact entry in one open database instance.
// It contains no private key or cached entry. Stores must validate every member
// authoritatively before a targeted assertion, with no cross-database fallback.
type CredentialReference struct {
	DatabaseUUID     string
	DatabaseInstance uint64
	EntryUUID        string
	RPID             string
	CredentialID     string
	UserHandle       string
}

// ResidentAssertion contains only the response material authorized by the caller.
type ResidentAssertion struct {
	CredentialID, UserHandle, AuthData, Signature []byte
	Name, DisplayName                             string
	SignCount                                     uint32
}

// CredentialStore is the persisted-credential surface the CTAP commands
// drive. Implementations enforce RP binding and persistence themselves.
// The command layer gates mutation/signing when the protocol requests checks;
// read-only lookups and silent assertions do not require gate approval.
type CredentialStore interface {
	// Create registers a new passkey for the RPID and returns the
	// credential ID, exact supplied user handle, and COSE-encoded public key.
	Create(rpID, rpName, userName, userDisplayName string, userID []byte, resident bool) (credentialID, userHandle, coseKey []byte, err error)

	// Assert signs for the credential matching rpID and credentialID
	// (nil credentialID selects the newest resident credential for the
	// RPID). userPresence and userVerified are independent established
	// verdicts; both false denotes a silent probe. Verification must be
	// reflected in the UV flag independently of presence. Returns the
	// credential ID actually used — resident lookups must surface it —
	// plus user handle, authenticator data, and signature. The store
	// refuses unknown or cross-RP credentials and returns
	// ErrNoCredentials when nothing matches.
	Assert(rpID string, credentialID, clientDataHash []byte, userPresence, userVerified bool) (usedCredentialID, userHandle, authenticatorData, signature []byte, err error)

	// ResidentCredentials returns newest-first opaque identities, never keys.
	ResidentCredentials(rpID string) ([]CredentialReference, error)
	// AssertResident validates every original reference and signs ref under one
	// storage consistency boundary, including counter persistence. Any unavailable
	// or changed original candidate refuses the entire series without signing.
	AssertResident(ref CredentialReference, original []CredentialReference, hash []byte, up, uv bool) (ResidentAssertion, error)

	// HasCredential reports whether the store holds a credential with
	// this exact RP-bound ID — used for excludeList enforcement during
	// MakeCredential.
	HasCredential(rpID string, credentialID []byte) (bool, error)

	// HasCredentialsForRPID reports whether any resident credential
	// exists for the RPID. Lookup is read-only; GetAssertion still obtains
	// requested consent before disclosing that no credential exists.
	HasCredentialsForRPID(rpID string) (bool, error)
}
