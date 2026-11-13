//go:build linux

// Package fido2 implements WebAuthn/FIDO2 software passkey functionality
// for kpxcd. Credentials live in KeePass entries (KPEX_PASSKEY_* custom
// value fields, KeePassXC-compatible layout plus a kpxcd sign-counter
// extension) and persist through the dbpool atomic write path.
//
// The package does not speak to browsers itself; a CTAP2 transport drives
// it. Every assertion requires the caller to present an established user
// presence: this package refuses to sign on its own authority.
package fido2

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/fxamacker/cbor/v2"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

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

	// IDBytes for credential IDs.
	IDBytes = 32

	// passkeyGroupName is the root-level group holding passkey entries.
	passkeyGroupName = "Passkeys"
)

// Custom data field keys matching the KeePassXC convention, plus the
// kpxcd sign counter (KPEX_PASSKEY_COUNTER), a kpxcd extension.
const (
	KPEXPrefix         = "KPEX_"
	KPEXPasskeyRPID    = "KPEX_PASSKEY_RPID"
	KPEXPasskeyRPName  = "KPEX_PASSKEY_RPNAME"
	KPEXPasskeyUser    = "KPEX_PASSKEY_USER"
	KPEXPasskeyHandle  = "KPEX_PASSKEY_HANDLE"
	KPEXPasskeyCredID  = "KPEX_PASSKEY_CRED_ID"
	KPEXPasskeyPrivKey = "KPEX_PASSKEY_PRIV_KEY"
	KPEXPasskeyPubKey  = "KPEX_PASSKEY_PUB_KEY"
	KPEXPasskeyCounter = "KPEX_PASSKEY_COUNTER"
)

// PasskeyEntry represents a stored passkey in a KeePass entry.
type PasskeyEntry struct {
	RPID          string // Relying Party ID (e.g. "github.com")
	RPName        string // Relying Party display name
	Username      string // User name
	UserHandle    string // Base64url-encoded user handle
	CredentialID  string // Base64url-encoded credential ID
	PrivateKeyPEM string // PEM-encoded private key (PKCS#8)
	PublicKeyCOSE []byte // COSE-encoded public key
	SignCount     uint32 // Last persisted signature counter
	Subject       string // Entry title for display
	DBUUID        string // Database UUID
	EntryUUID     string // KeePass entry UUID, hex
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

// CreatePasskey generates a new credential, persists it as a KeePass entry,
// and returns its metadata. The private key material is generated and
// encoded inside security.Do so registers and stack lose it promptly.
func (s *Fido2Service) CreatePasskey(dbUUID, rpID, rpName, userName, userDisplayName string, algorithms []int) (*PasskeyEntry, error) {
	if !s.config.Enabled {
		return nil, fmt.Errorf("fido2: service is disabled")
	}
	if rpID == "" {
		return nil, fmt.Errorf("fido2: rpID is required")
	}

	db, err := s.pool.Get(dbUUID)
	if err != nil {
		return nil, fmt.Errorf("fido2: database not found: %w", err)
	}

	// Determine algorithm (default to ES256).
	alg := COSEAlgES256
	if len(algorithms) > 0 {
		alg = algorithms[0]
	}

	var pubKeyCOSE []byte
	var privKeyPEM string
	var keyErr error

	security.Do(func() {
		pubKeyCOSE, privKeyPEM, keyErr = generateKeyPair(alg)
	})
	if keyErr != nil {
		return nil, fmt.Errorf("fido2: key generation failed: %w", keyErr)
	}

	credID, err := generateCredentialID()
	if err != nil {
		return nil, fmt.Errorf("fido2: %w", err)
	}
	userHandle, err := generateUserHandle()
	if err != nil {
		return nil, fmt.Errorf("fido2: %w", err)
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
		SignCount:     0,
	}

	if err := persistPasskey(db, entry); err != nil {
		return nil, fmt.Errorf("fido2: %w", err)
	}

	slog.Info("fido2: created passkey", "rpID", rpID, "username", userName)
	return entry, nil
}

// SignAssertionInput carries one assertion request. UserPresent is a gate
// output: the caller must have established user presence before calling.
type SignAssertionInput struct {
	RPID           string
	CredentialID   string // Base64url; empty selects a resident credential by RPID
	ClientDataHash []byte // SHA-256 of the client data JSON (32 bytes)
	UserPresent    bool
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

// AssertionResult is one signed WebAuthn assertion. All byte fields are
// raw; the CTAP transport encodes them.
type AssertionResult struct {
	CredentialID      []byte
	UserHandle        []byte
	AuthenticatorData []byte
	Signature         []byte
	SignCount         uint32
}

// SignAssertion signs one assertion for a stored credential and advances
// the persisted sign counter. It refuses unless user presence is claimed:
// without presence there is no assertion.
func (s *Fido2Service) SignAssertion(in SignAssertionInput) (*AssertionResult, error) {
	if !s.config.Enabled {
		return nil, fmt.Errorf("fido2: service is disabled")
	}
	if in.RPID == "" {
		return nil, fmt.Errorf("fido2: rpID is required")
	}
	if len(in.ClientDataHash) != sha256.Size {
		return nil, fmt.Errorf("fido2: client data hash must be %d bytes, got %d", sha256.Size, len(in.ClientDataHash))
	}
	if !in.UserPresent {
		return nil, fmt.Errorf("fido2: refusing to sign without user presence")
	}

	odb, entry, err := s.lookupCredential(in.RPID, in.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("fido2: %w", err)
	}

	// Advance the persisted counter before signing; an assertion whose
	// counter did not persist is an error, never a replayable signature.
	signCount, err := advanceSignCount(odb, entry)
	if err != nil {
		return nil, fmt.Errorf("fido2: %w", err)
	}

	var flags byte
	flags |= FlagUP
	if in.UserVerified {
		flags |= FlagUV
	}
	if in.BackupEligible {
		flags |= FlagBE
	}
	if in.BackupState {
		flags |= FlagBS
	}

	authData := buildAuthenticatorData(in.RPID, flags, signCount, nil)
	signature, err := signWithPrivateKey(entry.PrivateKeyPEM, authData, in.ClientDataHash)
	if err != nil {
		return nil, fmt.Errorf("fido2: assertion signing failed: %w", err)
	}

	credID, err := base64.RawURLEncoding.DecodeString(entry.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("fido2: stored credential ID is not base64url: %w", err)
	}
	userHandle, err := base64.RawURLEncoding.DecodeString(entry.UserHandle)
	if err != nil {
		return nil, fmt.Errorf("fido2: stored user handle is not base64url: %w", err)
	}

	slog.Info("fido2: signed assertion", "rpID", in.RPID, "signCount", signCount)
	return &AssertionResult{
		CredentialID:      credID,
		UserHandle:        userHandle,
		AuthenticatorData: authData,
		Signature:         signature,
		SignCount:         signCount,
	}, nil
}

// FindPasskeysByRPID finds all passkeys for a given relying party ID.
func (s *Fido2Service) FindPasskeysByRPID(dbUUID, rpID string) ([]*PasskeyEntry, error) {
	var results []*PasskeyEntry

	dbs := s.pool.List()
	for i := range dbs {
		if dbUUID != "" && dbs[i].UUID != dbUUID {
			continue
		}
		entries := dbs[i].RootEntries()
		for j := range entries {
			pk, err := extractPasskeyFromEntry(&entries[j])
			if err != nil {
				return nil, fmt.Errorf("fido2: database %s: %w", dbs[i].Name, err)
			}
			if pk == nil || pk.RPID != rpID {
				continue
			}
			pk.DBUUID = dbs[i].UUID
			pk.EntryUUID = fmt.Sprintf("%x", entries[j].UUID[:])
			results = append(results, pk)
		}
	}

	return results, nil
}

// FindPasskeyByCredentialID finds a passkey by its credential ID.
func (s *Fido2Service) FindPasskeyByCredentialID(credentialID string) (*PasskeyEntry, error) {
	dbs := s.pool.List()
	for i := range dbs {
		entries := dbs[i].RootEntries()
		for j := range entries {
			pk, err := extractPasskeyFromEntry(&entries[j])
			if err != nil {
				return nil, fmt.Errorf("fido2: database %s: %w", dbs[i].Name, err)
			}
			if pk == nil || pk.CredentialID != credentialID {
				continue
			}
			pk.DBUUID = dbs[i].UUID
			pk.EntryUUID = fmt.Sprintf("%x", entries[j].UUID[:])
			return pk, nil
		}
	}
	return nil, fmt.Errorf("fido2: passkey not found for credential ID: %s", credentialID)
}

// lookupCredential finds the open database and passkey for an assertion.
// An empty credential ID selects the newest resident credential for the
// RPID (D3: kpxcd credentials are resident by nature).
func (s *Fido2Service) lookupCredential(rpID, credentialID string) (*dbpool.OpenDatabase, *PasskeyEntry, error) {
	var (
		best      *PasskeyEntry
		bestEntry *gokeepasslib.Entry
		bestDB    string
	)
	dbs := s.pool.List()
	for i := range dbs {
		entries := dbs[i].RootEntries()
		for j := range entries {
			pk, err := extractPasskeyFromEntry(&entries[j])
			if err != nil {
				return nil, nil, fmt.Errorf("database %s: %w", dbs[i].Name, err)
			}
			if pk == nil || pk.RPID != rpID || pk.CredentialID == "" {
				continue
			}
			pk.DBUUID = dbs[i].UUID
			pk.EntryUUID = fmt.Sprintf("%x", entries[j].UUID[:])
			if credentialID != "" {
				if pk.CredentialID != credentialID {
					continue
				}
				odb, err := s.pool.Get(dbs[i].UUID)
				if err != nil {
					return nil, nil, fmt.Errorf("database not found: %w", err)
				}
				return odb, pk, nil
			}
			// Resident flow: the newest created credential for this RPID wins.
			if best == nil || newerThan(entries[j], *bestEntry) {
				best, bestEntry, bestDB = pk, &entries[j], dbs[i].UUID
			}
		}
	}
	if best == nil {
		return nil, nil, fmt.Errorf("no passkey for rpID %q", rpID)
	}
	odb, err := s.pool.Get(bestDB)
	if err != nil {
		return nil, nil, fmt.Errorf("database not found: %w", err)
	}
	return odb, best, nil
}

// persistPasskey writes a new passkey entry into the Passkeys group.
func persistPasskey(db *dbpool.OpenDatabase, pk *PasskeyEntry) error {
	err := db.UpdateAndSave(func(db *gokeepasslib.Database) error {
		group := findOrCreatePasskeyGroup(db)
		entry := newPasskeyEntry(pk)
		group.Entries = append(group.Entries, entry)
		return nil
	})
	if err != nil {
		return fmt.Errorf("persist passkey: %w", err)
	}
	return nil
}

// advanceSignCount increments the persisted sign counter and returns the
// new value. The entry is located in its database by UUID; the counter
// field must exist and stay monotonic.
func advanceSignCount(db *dbpool.OpenDatabase, pk *PasskeyEntry) (uint32, error) {
	var newCount uint32
	err := db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		entry := findEntryByUUIDHex(&kdb.Content.Root.Groups, pk.EntryUUID)
		if entry == nil {
			return fmt.Errorf("entry %s disappeared", pk.EntryUUID)
		}
		current, err := readSignCount(entry)
		if err != nil {
			return err
		}
		newCount = current + 1
		setEntryValue(entry, KPEXPasskeyCounter, fmt.Sprintf("%d", newCount), false)
		now := wrappers.Now()
		entry.Times.LastModificationTime = &now
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("advance sign counter: %w", err)
	}
	return newCount, nil
}

// readSignCount parses the counter field. A missing field is a hard error:
// the counter must never silently restart.
func readSignCount(entry *gokeepasslib.Entry) (uint32, error) {
	raw := entry.GetContent(KPEXPasskeyCounter)
	if raw == "" {
		return 0, fmt.Errorf("passkey entry %q has no sign counter", entry.GetTitle())
	}
	var count uint32
	if _, err := fmt.Sscanf(raw, "%d", &count); err != nil {
		return 0, fmt.Errorf("passkey entry %q has malformed sign counter %q", entry.GetTitle(), raw)
	}
	return count, nil
}

// extractPasskeyFromEntry reads passkey data from KeePass entry value
// fields. It returns (nil, nil) for entries without passkey data and a
// hard error for entries with partial data.
func extractPasskeyFromEntry(entry *gokeepasslib.Entry) (*PasskeyEntry, error) {
	rpID := entry.GetContent(KPEXPasskeyRPID)
	if rpID == "" {
		return nil, nil // not a passkey entry
	}

	pk := &PasskeyEntry{
		RPID:     rpID,
		RPName:   entry.GetContent(KPEXPasskeyRPName),
		Username: entry.GetContent(KPEXPasskeyUser),
	}
	for _, field := range []struct {
		key string
		dst *string
	}{
		{KPEXPasskeyHandle, &pk.UserHandle},
		{KPEXPasskeyCredID, &pk.CredentialID},
		{KPEXPasskeyPrivKey, &pk.PrivateKeyPEM},
	} {
		*field.dst = entry.GetContent(field.key)
		if *field.dst == "" {
			return nil, fmt.Errorf("passkey entry %q is missing %s", entry.GetTitle(), field.key)
		}
	}

	coseB64 := entry.GetContent(KPEXPasskeyPubKey)
	if coseB64 == "" {
		return nil, fmt.Errorf("passkey entry %q is missing %s", entry.GetTitle(), KPEXPasskeyPubKey)
	}
	cose, err := base64.StdEncoding.DecodeString(coseB64)
	if err != nil {
		return nil, fmt.Errorf("passkey entry %q has malformed public key: %w", entry.GetTitle(), err)
	}
	pk.PublicKeyCOSE = cose

	count, err := readSignCount(entry)
	if err != nil {
		return nil, err
	}
	pk.SignCount = count

	pk.Subject = entry.GetTitle()
	return pk, nil
}

// newPasskeyEntry builds the KeePass entry for a freshly created passkey.
func newPasskeyEntry(pk *PasskeyEntry) gokeepasslib.Entry {
	entry := gokeepasslib.NewEntry()

	title := pk.RPName
	if title == "" {
		title = pk.RPID
	}
	set := func(key, value string, protected bool) { setEntryValue(&entry, key, value, protected) }

	set("Title", title, false)
	set("UserName", pk.Username, false)
	set("URL", "https://"+pk.RPID, false)
	set("Password", "", false)
	set(KPEXPasskeyRPID, pk.RPID, false)
	set(KPEXPasskeyRPName, pk.RPName, false)
	set(KPEXPasskeyUser, pk.Username, false)
	set(KPEXPasskeyHandle, pk.UserHandle, false)
	set(KPEXPasskeyCredID, pk.CredentialID, false)
	set(KPEXPasskeyPrivKey, pk.PrivateKeyPEM, true)
	set(KPEXPasskeyPubKey, base64.StdEncoding.EncodeToString(pk.PublicKeyCOSE), false)
	set(KPEXPasskeyCounter, "0", false)

	return entry
}

// setEntryValue sets an entry value field, replacing an existing value
// with the same key (same pattern as the Secret Service write path).
func setEntryValue(entry *gokeepasslib.Entry, key, value string, protected bool) {
	idx := entry.GetIndex(key)
	v := gokeepasslib.ValueData{
		Key: key,
		Value: gokeepasslib.V{
			Content:   value,
			Protected: wrappers.BoolWrapper{Bool: protected},
		},
	}
	if idx >= 0 {
		entry.Values[idx] = v
		return
	}
	entry.Values = append(entry.Values, v)
}

// findOrCreatePasskeyGroup returns the root-level Passkeys group.
func findOrCreatePasskeyGroup(db *gokeepasslib.Database) *gokeepasslib.Group {
	if db.Content == nil {
		db.Content = gokeepasslib.NewContent()
	}
	if db.Content.Root == nil {
		db.Content.Root = gokeepasslib.NewRootData()
	}
	if len(db.Content.Root.Groups) == 0 {
		root := gokeepasslib.NewGroup()
		root.Name = "Root"
		db.Content.Root.Groups = append(db.Content.Root.Groups, root)
	}
	root := &db.Content.Root.Groups[0]
	for i := range root.Groups {
		if root.Groups[i].Name == passkeyGroupName {
			return &root.Groups[i]
		}
	}
	group := gokeepasslib.NewGroup()
	group.Name = passkeyGroupName
	root.Groups = append(root.Groups, group)
	return &root.Groups[len(root.Groups)-1]
}

// findEntryByUUIDHex locates an entry by its hex UUID across groups.
func findEntryByUUIDHex(groups *[]gokeepasslib.Group, uuidHex string) *gokeepasslib.Entry {
	for gi := range *groups {
		group := &(*groups)[gi]
		for ei := range group.Entries {
			if fmt.Sprintf("%x", group.Entries[ei].UUID[:]) == uuidHex {
				return &group.Entries[ei]
			}
		}
		if found := findEntryByUUIDHex(&group.Groups, uuidHex); found != nil {
			return found
		}
	}
	return nil
}

// generateKeyPair generates an ES256 or Ed25519 key pair and encodes the
// private key as PKCS#8 PEM (D2) and the public key as COSE.
func generateKeyPair(alg int) (pubKeyCOSE []byte, privKeyPEM string, err error) {
	switch alg {
	case COSEAlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", err
		}
		pub, err := encodeECDSAPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, "", err
		}
		return pub, encodePEM("PRIVATE KEY", der), nil

	case COSEAlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		cosePub, err := encodeEd25519PublicKey(pub)
		if err != nil {
			return nil, "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, "", err
		}
		return cosePub, encodePEM("PRIVATE KEY", der), nil

	default:
		return nil, "", fmt.Errorf("unsupported algorithm: %d", alg)
	}
}

// encodePEM wraps DER bytes in a PEM block.
func encodePEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// signWithPrivateKey signs authData || clientDataHash with a stored PKCS#8
// private key: ECDSA/ASN.1 for ES256, raw RFC 8032 for Ed25519. The private
// key bytes are parsed inside security.Do.
func signWithPrivateKey(privKeyPEM string, authData, clientDataHash []byte) ([]byte, error) {
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash...)

	var signature []byte
	var signErr error
	security.Do(func() {
		block, _ := pem.Decode([]byte(privKeyPEM))
		if block == nil {
			signErr = fmt.Errorf("stored private key is not valid PEM")
			return
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			signErr = fmt.Errorf("stored private key does not parse: %w", err)
			return
		}
		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			digest := sha256.Sum256(signed)
			sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
			if err != nil {
				signErr = err
				return
			}
			signature = sig
		case ed25519.PrivateKey:
			signature = ed25519.Sign(key, signed)
		default:
			signErr = fmt.Errorf("stored private key has unsupported type %T", key)
		}
	})
	if signErr != nil {
		return nil, signErr
	}
	return signature, nil
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

// buildAuthenticatorData constructs the authenticator data bytes:
// rpIDHash (32) + flags (1) + signCount (4) + optional extensions.
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

// newerThan reports whether entry a was created after entry b.
func newerThan(a, b gokeepasslib.Entry) bool {
	if a.Times.CreationTime == nil || b.Times.CreationTime == nil {
		return false
	}
	return a.Times.CreationTime.Time.After(b.Times.CreationTime.Time)
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
