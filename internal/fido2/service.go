//go:build linux

// Package fido2 implements WebAuthn/FIDO2 software passkey functionality
// for kpxcd, allowing credential creation and assertion using keys
// stored in KeePass entries.
package fido2

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/fxamacker/cbor/v2"
	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/security"
)

// Constants for WebAuthn/FIDO2.
const (
	// AAGUID for kpxcd software authenticator (matches KeePassXC convention).
	DefaultAAGUID = "f8a011f3-8c0a-4d15-8006-17111f9edc7d"

	// COSE algorithm identifiers.
	COSEAlgES256  = -7  // ECDSA w/ SHA-256
	COSEAlgES256K = -25 // ECDSA w/ secp256k1
	COSEAlgPS256  = -37 // RSASSA-PSS w/ SHA-256
	COSEAlgEdDSA  = -8  // EdDSA (Ed25519)

	// Authenticator flags.
	FlagUP = 0x01 // User Present
	FlagUV = 0x04 // User Verified
	FlagBE = 0x08 // Backup Eligible
	FlagBS = 0x10 // Backup State
	FlagAT = 0x40 // Attested Credential Data
	FlagED = 0x80 // Extension Data

	// ID bytes for credential IDs.
	IDBytes = 32
)

// PasskeyEntry represents a stored passkey in a KeePass entry.
type PasskeyEntry struct {
	RPID          string // Relying Party ID (e.g., "github.com")
	RPName        string // Relying Party display name
	Username      string // User name
	UserHandle    string // Base64url-encoded user handle
	CredentialID  string // Base64url-encoded credential ID
	PrivateKeyPEM string // PEM-encoded private key
	PublicKeyCOSE []byte // COSE-encoded public key
	Subject       string // Entry title for display
	DBUUID        string // Database UUID
	EntryUUID     string // Entry UUID
}

// Fido2Service provides FIDO2/WebAuthn passkey operations.
type Fido2Service struct {
	config *config.Fido2Config
	pool   *dbpool.DatabasePool
}

// NewFido2Service creates a new FIDO2 service.
func NewFido2Service(cfg *config.Fido2Config, pool *dbpool.DatabasePool) *Fido2Service {
	return &Fido2Service{
		config: cfg,
		pool:   pool,
	}
}

// CreatePasskey creates a new FIDO2 credential and stores it in the database.
func (s *Fido2Service) CreatePasskey(dbUUID, rpID, rpName, userName, userDisplayName string, algorithms []int) (*PasskeyEntry, error) {
	if !s.config.Enabled {
		return nil, fmt.Errorf("fido2: service is disabled")
	}

	db, err := s.pool.Get(dbUUID)
	if err != nil {
		return nil, fmt.Errorf("fido2: database not found: %w", err)
	}

	// Generate credential ID (32 random bytes, base64url encoded).
	credID, err := generateCredentialID()
	if err != nil {
		return nil, fmt.Errorf("fido2: %w", err)
	}

	// Generate user handle (random 64-bit, base64url encoded).
	userHandle, err := generateUserHandle()
	if err != nil {
		return nil, fmt.Errorf("fido2: %w", err)
	}

	// Determine algorithm (default to ES256).
	alg := COSEAlgES256
	if len(algorithms) > 0 {
		alg = algorithms[0]
	}

	// Generate key pair inside security.Do() so private key material
	// is zeroed from registers and stack after use.
	var pubKeyCOSE []byte
	var privKeyPEM string
	var keyErr error

	security.Do(func() {
		switch alg {
		case COSEAlgES256:
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				keyErr = err
				return
			}
			pubKeyCOSE, err = encodeECDSAPublicKey(&priv.PublicKey)
			if err != nil {
				keyErr = err
				return
			}
			privKeyPEM, err = encodeECDSAPrivateKey(priv)
			if err != nil {
				keyErr = err
				return
			}

		case COSEAlgEdDSA:
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				keyErr = err
				return
			}
			pubKeyCOSE, err = encodeEd25519PublicKey(pub)
			if err != nil {
				keyErr = err
				return
			}
			privKeyPEM, err = encodeEd25519PrivateKey(priv)
			if err != nil {
				keyErr = err
				return
			}

		default:
			keyErr = fmt.Errorf("fido2: unsupported algorithm: %d", alg)
			return
		}
	})

	if keyErr != nil {
		return nil, fmt.Errorf("fido2: key generation failed: %w", keyErr)
	}

	entry := &PasskeyEntry{
		RPID:          rpID,
		RPName:        rpName,
		Username:      userName,
		UserHandle:    userHandle,
		CredentialID:  credID,
		PrivateKeyPEM: privKeyPEM,
		PublicKeyCOSE: pubKeyCOSE,
		Subject:       userDisplayName,
		DBUUID:        dbUUID,
	}

	// Store the passkey data in KeePass custom data fields.
	storePasskeyInEntry(db, entry, rpID, rpName, userName, userDisplayName)

	slog.Info("FIDO2: created passkey",
		"rpID", rpID,
		"username", userName,
		"credentialID", credID)

	return entry, nil
}

// AssertPasskey performs a FIDO2 assertion (authentication) using a stored passkey.
func (s *Fido2Service) AssertPasskey(rpID, credentialID, challenge, origin string) (*AssertionResult, error) {
	if !s.config.Enabled {
		return nil, fmt.Errorf("fido2: service is disabled")
	}

	// Find the passkey entry across all databases.
	entry, err := s.FindPasskeyByCredentialID(credentialID)
	if err != nil {
		return nil, fmt.Errorf("fido2: passkey not found: %w", err)
	}

	// Build authenticator data.
	flags := byte(FlagUP | FlagUV | FlagBE | FlagBS)
	authData := buildAuthenticatorData(rpID, flags, 0, nil)

	// Sign the challenge with the private key.
	clientDataJSON := buildClientDataJSON("webauthn.get", challenge, origin)
	clientDataHash := sha256.Sum256([]byte(clientDataJSON))
	signedData := append(authData, clientDataHash[:32]...)

	signature, err := signAssertion(entry.PrivateKeyPEM, entry.PublicKeyCOSE, signedData)
	if err != nil {
		return nil, fmt.Errorf("fido2: assertion signing failed: %w", err)
	}

	result := &AssertionResult{
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
		Signature:         base64.RawURLEncoding.EncodeToString(signature),
		UserHandle:        entry.UserHandle,
		CredentialID:      entry.CredentialID,
	}

	slog.Info("FIDO2: asserted passkey", "rpID", rpID, "credentialID", credentialID)
	return result, nil
}

// FindPasskeysByRPID finds all passkeys for a given relying party ID.
func (s *Fido2Service) FindPasskeysByRPID(dbUUID, rpID string) ([]*PasskeyEntry, error) {
	var results []*PasskeyEntry

	dbs := s.pool.List()
	for _, db := range dbs {
		if dbUUID != "" && db.UUID != dbUUID {
			continue
		}
		entries := db.RootEntries()
		for i := range entries {
			pk, err := extractPasskeyFromEntry(&entries[i])
			if err != nil || pk == nil {
				continue
			}
			if pk.RPID == rpID {
				pk.DBUUID = db.UUID
				pk.EntryUUID = string(entries[i].UUID[:])
				results = append(results, pk)
			}
		}
	}

	return results, nil
}

// FindPassKeyByCredentialID finds a passkey by its credential ID.
func (s *Fido2Service) FindPasskeyByCredentialID(credentialID string) (*PasskeyEntry, error) {
	dbs := s.pool.List()
	for _, db := range dbs {
		entries := db.RootEntries()
		for i := range entries {
			pk, err := extractPasskeyFromEntry(&entries[i])
			if err != nil || pk == nil {
				continue
			}
			if pk.CredentialID == credentialID {
				pk.DBUUID = db.UUID
				pk.EntryUUID = string(entries[i].UUID[:])
				return pk, nil
			}
		}
	}
	return nil, fmt.Errorf("fido2: passkey not found for credential ID: %s", credentialID)
}

// AssertionResult contains the result of a passkey assertion.
type AssertionResult struct {
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"user_handle"`
	CredentialID      string `json:"credential_id"`
}

// generateCredentialID generates a random 32-byte credential ID, base64url encoded.
func generateCredentialID() (string, error) {
	b := make([]byte, IDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate credential ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateUserHandle generates a random 8-byte user handle, base64url encoded.
func generateUserHandle() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate user handle: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// buildAuthenticatorData constructs the authenticator data bytes.
func buildAuthenticatorData(rpID string, flags byte, signCount uint32, extensions []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	data := make([]byte, 0, 37+len(extensions))
	data = append(data, rpIDHash[:]...)
	data = append(data, flags)
	data = append(data, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	if extensions != nil {
		data = append(data, extensions...)
	}
	return data
}

// buildClientDataJSON constructs the client data JSON for WebAuthn.
func buildClientDataJSON(typ, challenge, origin string) string {
	cd := map[string]string{
		"type":        typ,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": "false",
	}
	b, _ := json.Marshal(cd)
	return string(b)
}

// COSE key structure for ECDSA P-256.
type coseEC2Key struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
	Alg int    `cbor:"3,keyasint"`
}

// COSE key structure for Ed25519 (OKP).
type coseOKPKey struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Alg int    `cbor:"3,keyasint"`
}

// encodeECDSAPublicKey encodes an ECDSA P-256 public key as a COSE key.
func encodeECDSAPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	key := coseEC2Key{
		Kty: 2, // EC2
		Crv: 1, // P-256
		X:   pub.X.Bytes(),
		Y:   pub.Y.Bytes(),
		Alg: COSEAlgES256,
	}
	return cbor.Marshal(key)
}

// encodeEd25519PublicKey encodes an Ed25519 public key as a COSE key.
func encodeEd25519PublicKey(pub ed25519.PublicKey) ([]byte, error) {
	key := coseOKPKey{
		Kty: 1, // OKP
		Crv: 6, // Ed25519
		X:   pub,
		Alg: COSEAlgEdDSA,
	}
	return cbor.Marshal(key)
}

// Custom data field prefixes matching KeePassXC convention.
const (
	KPEXPrefix         = "KPEX_"
	KPEXPasskeyRPID    = "KPEX_PASSKEY_RPID"
	KPEXPasskeyRPName  = "KPEX_PASSKEY_RPNAME"
	KPEXPasskeyUser    = "KPEX_PASSKEY_USER"
	KPEXPasskeyHandle  = "KPEX_PASSKEY_HANDLE"
	KPEXPasskeyCredID  = "KPEX_PASSKEY_CRED_ID"
	KPEXPasskeyPrivKey = "KPEX_PASSKEY_PRIV_KEY"
	KPEXPasskeyPubKey  = "KPEX_PASSKEY_PUB_KEY"
)

// storePasskeyInEntry stores passkey data in a KeePass entry's custom data fields.
// Note: This only stores the data in memory — the database is read-only in kpxcd,
// so this is for future use when the DB is written back.
func storePasskeyInEntry(_ *dbpool.OpenDatabase, _ *PasskeyEntry, _, _, _, _ string) {
	// kpxcd is read-only — this would need to be done via the GUI or CLI.
	// We store the passkey data in the PasskeyEntry struct and return it to the caller.
	slog.Warn("FIDO2: passkey storage in database is not yet implemented (read-only mode)")
}

// extractPasskeyFromEntry extracts passkey data from KeePass entry custom data.
func extractPasskeyFromEntry(entry interface {
	GetContent(key string) string
}) (*PasskeyEntry, error) {
	_ = entry
	// This function will need the actual entry type when integrated.
	// For now, return nil to indicate no passkey found.
	return nil, nil
}

// signAssertion signs the assertion data with the private key.
func signAssertion(privKeyPEM string, pubKeyCOSE []byte, data []byte) ([]byte, error) {
	// TODO: Implement actual signing using the private key from PEM.
	// For now, use Go's crypto/ecdsa or crypto/ed25519 depending on the COSE algorithm.
	switch {
	case len(pubKeyCOSE) > 0:
		// Decode the COSE key to determine algorithm and sign.
		return signWithCOSEKey(privKeyPEM, pubKeyCOSE, data)
	default:
		return nil, fmt.Errorf("fido2: no public key available for signing")
	}
}

// signWithCOSEKey decodes the COSE key, determines the algorithm, and signs.
func signWithCOSEKey(privKeyPEM string, pubKeyCOSE []byte, data []byte) ([]byte, error) {
	// Try to determine the algorithm from the COSE key.
	// For now, return a placeholder.
	_ = privKeyPEM
	_ = data
	return nil, fmt.Errorf("fido2: assertion signing not yet fully implemented")
}

// encodeECDSAPrivateKey encodes an ECDSA private key as PEM.
func encodeECDSAPrivateKey(key *ecdsa.PrivateKey) (string, error) {
	// Use x509.MarshalECPrivateKey for the simplest encoding.
	der, err := x509MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return "-----BEGIN EC PRIVATE KEY-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END EC PRIVATE KEY-----", nil
}

// encodeEd25519PrivateKey encodes an Ed25519 private key as PEM.
func encodeEd25519PrivateKey(key ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return "-----BEGIN PRIVATE KEY-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END PRIVATE KEY-----", nil
}

// x509MarshalECPrivateKey wraps x509.MarshalECPrivateKey.
func x509MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(key)
}
