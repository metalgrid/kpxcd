//go:build linux

package fido2

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2/hid"
)

// CtapStore adapts Fido2Service to the CTAP2 transport's CredentialStore
// interface. Registrations land in the configured default database
// (resolved lazily; the database may unlock after daemon start).
//
// Every transport call site is behind the presence gate, so user presence
// is already established when these methods run.
type CtapStore struct {
	svc         *Fido2Service
	pool        *dbpool.DatabasePool
	defaultPath string
}

// NewCtapStore builds the adapter. defaultPath selects which database
// receives new registrations; empty falls back to the first open database.
func NewCtapStore(svc *Fido2Service, pool *dbpool.DatabasePool, defaultPath string) *CtapStore {
	return &CtapStore{svc: svc, pool: pool, defaultPath: defaultPath}
}

// Create implements hid.CredentialStore.
func (c *CtapStore) Create(rpID, rpName, userName, userDisplayName string) ([]byte, []byte, []byte, error) {
	dbUUID, err := c.defaultDB()
	if err != nil {
		return nil, nil, nil, err
	}
	entry, err := c.svc.CreatePasskey(dbUUID, rpID, rpName, userName, userDisplayName, []int{COSEAlgES256})
	if err != nil {
		return nil, nil, nil, err
	}
	credID, err := base64.RawURLEncoding.DecodeString(entry.CredentialID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fido2: created credential ID is not base64url: %w", err)
	}
	userHandle, err := base64.RawURLEncoding.DecodeString(entry.UserHandle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fido2: created user handle is not base64url: %w", err)
	}
	return credID, userHandle, entry.PublicKeyCOSE, nil
}

// Assert implements hid.CredentialStore. User presence is established by
// the gate before the transport calls this.
func (c *CtapStore) Assert(rpID string, credentialID, clientDataHash []byte, userVerified bool) ([]byte, []byte, []byte, []byte, error) {
	credIDStr := ""
	if credentialID != nil {
		credIDStr = base64.RawURLEncoding.EncodeToString(credentialID)
	}
	res, err := c.svc.SignAssertion(SignAssertionInput{
		RPID:           rpID,
		CredentialID:   credIDStr,
		ClientDataHash: clientDataHash,
		UserPresent:    true, // gate output, checked upstream
		UserVerified:   userVerified,
	})
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return nil, nil, nil, nil, hid.ErrNoCredentials
		}
		return nil, nil, nil, nil, err
	}
	return res.CredentialID, res.UserHandle, res.AuthenticatorData, res.Signature, nil
}

// HasCredentialsForRPID implements hid.CredentialStore.
func (c *CtapStore) HasCredentialsForRPID(rpID string) (bool, error) {
	found, err := c.svc.FindPasskeysByRPID("", rpID)
	if err != nil {
		return false, err
	}
	return len(found) > 0, nil
}

// defaultDB resolves the registration database UUID at call time.
func (c *CtapStore) defaultDB() (string, error) {
	dbs := c.pool.List()
	if len(dbs) == 0 {
		return "", errors.New("fido2: no unlocked database for passkey registration")
	}
	if c.defaultPath != "" {
		for i := range dbs {
			if dbs[i].Path == c.defaultPath {
				return dbs[i].UUID, nil
			}
		}
	}
	return dbs[0].UUID, nil
}
