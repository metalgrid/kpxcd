//go:build linux

package fido2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/metalgrid/kpxcd/internal/xdg"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2/hid"
)

// CtapStore adapts Fido2Service to the CTAP2 transport's CredentialStore
// interface. Registrations land in the configured default database
// (resolved lazily; the database may unlock after daemon start).
//
// The transport establishes requested UP/UV properties before creation or
// signing. Silent assertions deliberately establish neither property.
type CtapStore struct {
	svc         *Fido2Service
	pool        *dbpool.DatabasePool
	defaultPath string
}

// NewCtapStore builds the adapter. defaultPath selects which database
// receives new registrations; an empty or unavailable selection refuses creation.
func NewCtapStore(svc *Fido2Service, pool *dbpool.DatabasePool, defaultPath string) *CtapStore {
	return &CtapStore{svc: svc, pool: pool, defaultPath: defaultPath}
}

// Create implements hid.CredentialStore.
func (c *CtapStore) Create(rpID, rpName, userName, userDisplayName string, userID []byte, resident bool) ([]byte, []byte, []byte, error) {
	if len(userID) < 1 || len(userID) > 64 {
		return nil, nil, nil, fmt.Errorf("fido2: user handle must be 1..64 bytes, got %d", len(userID))
	}
	// RP IDs are opaque to this adapter. No browser probe may shadow a
	// legitimate RP credential with an unpersisted, unusable key.

	db, err := c.defaultDB()
	if err != nil {
		return nil, nil, nil, err
	}
	entry, err := c.svc.createPasskey(db, rpID, rpName, userName, userDisplayName, userID, []int{COSEAlgES256}, resident)
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

// Assert implements hid.CredentialStore. The transport supplies independent
// UP/UV verdicts from its gate, or neither for a silent credential probe.
func (c *CtapStore) Assert(rpID string, credentialID, clientDataHash []byte, userPresence, userVerified bool) ([]byte, []byte, []byte, []byte, error) {
	credIDStr := ""
	if credentialID != nil {
		credIDStr = base64.RawURLEncoding.EncodeToString(credentialID)
	}
	res, err := c.svc.SignAssertion(SignAssertionInput{
		RPID:           rpID,
		CredentialID:   credIDStr,
		ClientDataHash: clientDataHash,
		UserPresent:    userPresence, // gate output, checked upstream
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

// ResidentCredentials implements identifier-only CTAP account enumeration.
func (c *CtapStore) ResidentCredentials(rpID string) ([]hid.CredentialReference, error) {
	return c.svc.residentCredentials(rpID)
}

// AssertResident refuses stale or unavailable candidates without another lookup.
func (c *CtapStore) AssertResident(ref hid.CredentialReference, original []hid.CredentialReference, hash []byte, up, uv bool) (hid.ResidentAssertion, error) {
	result, err := c.svc.assertResident(ref, original, hash, up, uv)
	if errors.Is(err, ErrNoCredentials) {
		return hid.ResidentAssertion{}, hid.ErrNoCredentials
	}
	return result, err
}

// HasCredentialsForRPID implements hid.CredentialStore.
func (c *CtapStore) HasCredentialsForRPID(rpID string) (bool, error) {
	found, err := c.svc.FindPasskeysByRPID("", rpID)
	if err != nil {
		return false, err
	}
	return len(found) > 0, nil
}

// HasCredential implements hid.CredentialStore for excludeList
// enforcement: reports whether this exact credential ID is bound to the RP.
func (c *CtapStore) HasCredential(rpID string, credentialID []byte) (bool, error) {
	if len(credentialID) == 0 {
		return false, nil
	}
	_, _, err := c.svc.lookupCredential(rpID, base64.RawURLEncoding.EncodeToString(credentialID))
	if errors.Is(err, ErrNoCredentials) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// defaultDB resolves the exact registration database open instance.
func (c *CtapStore) defaultDB() (*dbpool.OpenDatabase, error) {
	if c.defaultPath == "" {
		return nil, errors.New("fido2: no selected registration database")
	}
	// Match the same expansion used by configuration, without resolving symlinks
	// or guessing from map iteration. Availability is rechecked during mutation.
	path := filepath.Clean(xdg.ExpandPath(c.defaultPath))
	var selected *dbpool.OpenDatabase
	err := c.pool.WithUnlockedDatabases(func(dbs []*dbpool.OpenDatabase) error {
		for _, db := range dbs {
			if filepath.Clean(xdg.ExpandPath(db.Path)) == path {
				if selected != nil {
					return errors.New("fido2: ambiguous registration destination")
				}
				selected = db
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if selected == nil {
		return nil, errors.New("fido2: selected registration database is unavailable")
	}
	return selected, nil
}
