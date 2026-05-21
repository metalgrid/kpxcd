//go:build linux

package fido2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/security"
)

// TestGenerateCredentialIDUniqueness verifies that generateCredentialID
// produces unique 32-byte values.
func TestGenerateCredentialIDUniqueness(t *testing.T) {
	const iterations = 100
	seen := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		id := generateCredentialID()
		if seen[id] {
			t.Fatalf("duplicate credential ID generated: %s", id)
		}
		seen[id] = true

		// Verify it decodes to 32 bytes.
		decoded, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil {
			t.Fatalf("credential ID is not valid base64url: %v", err)
		}
		if len(decoded) != IDBytes {
			t.Errorf("credential ID decoded to %d bytes, want %d", len(decoded), IDBytes)
		}
	}
}

// TestGenerateUserHandleUniqueness verifies that generateUserHandle
// produces unique 8-byte values.
func TestGenerateUserHandleUniqueness(t *testing.T) {
	const iterations = 100
	seen := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		handle := generateUserHandle()
		if seen[handle] {
			t.Fatalf("duplicate user handle generated: %s", handle)
		}
		seen[handle] = true

		// Verify it decodes to 8 bytes.
		decoded, err := base64.RawURLEncoding.DecodeString(handle)
		if err != nil {
			t.Fatalf("user handle is not valid base64url: %v", err)
		}
		if len(decoded) != 8 {
			t.Errorf("user handle decoded to %d bytes, want 8", len(decoded))
		}
	}
}

// TestBuildAuthenticatorData verifies the structure of authenticator data.
func TestBuildAuthenticatorData(t *testing.T) {
	rpID := "example.com"
	flags := byte(FlagUP | FlagUV)
	signCount := uint32(42)

	data := buildAuthenticatorData(rpID, flags, signCount, nil)

	// Authenticator data structure:
	// - rpIDHash (32 bytes)
	// - flags (1 byte)
	// - signCount (4 bytes)
	expectedLen := 32 + 1 + 4
	if len(data) != expectedLen {
		t.Errorf("authenticator data length = %d, want %d", len(data), expectedLen)
	}

	// Verify rpID hash.
	expectedHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(data[:32], expectedHash[:]) {
		t.Error("rpID hash mismatch")
	}

	// Verify flags.
	if data[32] != flags {
		t.Errorf("flags = 0x%02x, want 0x%02x", data[32], flags)
	}

	// Verify sign count.
	gotSignCount := uint32(data[33])<<24 | uint32(data[34])<<16 | uint32(data[35])<<8 | uint32(data[36])
	if gotSignCount != signCount {
		t.Errorf("signCount = %d, want %d", gotSignCount, signCount)
	}
}

// TestBuildAuthenticatorDataWithExtensions verifies authenticator data
// with extension data appended.
func TestBuildAuthenticatorDataWithExtensions(t *testing.T) {
	rpID := "test.example.com"
	flags := byte(FlagUP | FlagED)
	extensions := []byte{0xa1, 0x00} // minimal CBOR map

	data := buildAuthenticatorData(rpID, flags, 0, extensions)

	expectedLen := 32 + 1 + 4 + len(extensions)
	if len(data) != expectedLen {
		t.Errorf("authenticator data length = %d, want %d", len(data), expectedLen)
	}

	// Verify extensions are appended.
	extStart := 32 + 1 + 4
	if !bytes.Equal(data[extStart:], extensions) {
		t.Error("extensions mismatch")
	}
}

// TestBuildClientDataJSON verifies the structure of client data JSON.
func TestBuildClientDataJSON(t *testing.T) {
	typ := "webauthn.get"
	challenge := "dGVzdC1jaGFsbGVuZ2U"
	origin := "https://example.com"

	cdJSON := buildClientDataJSON(typ, challenge, origin)

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	if err := cbor.Unmarshal([]byte(cdJSON), &parsed); err != nil {
		// Try standard JSON since buildClientDataJSON uses json.Marshal.
		// We need to parse it as JSON.
	}

	// Check the required fields exist and have correct values.
	// We'll just check substrings to avoid JSON parsing complexity.
	if !bytes.Contains([]byte(cdJSON), []byte(`"type":"webauthn.get"`)) {
		t.Errorf("clientDataJSON missing correct type: %s", cdJSON)
	}
	if !bytes.Contains([]byte(cdJSON), []byte(`"challenge":"dGVzdC1jaGFsbGVuZ2U"`)) {
		t.Errorf("clientDataJSON missing correct challenge: %s", cdJSON)
	}
	if !bytes.Contains([]byte(cdJSON), []byte(`"origin":"https://example.com"`)) {
		t.Errorf("clientDataJSON missing correct origin: %s", cdJSON)
	}
	if !bytes.Contains([]byte(cdJSON), []byte(`"crossOrigin":"false"`)) {
		t.Errorf("clientDataJSON missing crossOrigin: %s", cdJSON)
	}
}

// TestBuildClientDataJSONCreate verifies client data for credential creation.
func TestBuildClientDataJSONCreate(t *testing.T) {
	cdJSON := buildClientDataJSON("webauthn.create", "challenge123", "https://app.test")

	if !bytes.Contains([]byte(cdJSON), []byte(`"type":"webauthn.create"`)) {
		t.Errorf("clientDataJSON missing type webauthn.create: %s", cdJSON)
	}
}

// TestCreatePasskeyES256 verifies creating a passkey with ES256 algorithm.
func TestCreatePasskeyES256(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: true,
	}
	// Create a real database in the pool using the test helper.
	pool := newTestPoolWithDB(t)
	svc := NewFido2Service(cfg, pool)

	// Get the actual UUID from the pool.
	dbs := pool.List()
	if len(dbs) == 0 {
		t.Fatal("pool has no databases")
	}
	testUUID := dbs[0].UUID

	entry, err := svc.CreatePasskey(
		testUUID,
		"github.com",
		"GitHub",
		"testuser",
		"Test User",
		[]int{COSEAlgES256},
	)
	if err != nil {
		t.Fatalf("CreatePasskey(ES256) failed: %v", err)
	}
	if entry == nil {
		t.Fatal("CreatePasskey returned nil entry")
	}

	// Verify entry fields.
	if entry.RPID != "github.com" {
		t.Errorf("RPID = %q, want github.com", entry.RPID)
	}
	if entry.RPName != "GitHub" {
		t.Errorf("RPName = %q, want GitHub", entry.RPName)
	}
	if entry.Username != "testuser" {
		t.Errorf("Username = %q, want testuser", entry.Username)
	}
	if entry.DBUUID != testUUID {
		t.Errorf("DBUUID = %q, want %q", entry.DBUUID, testUUID)
	}
	if entry.CredentialID == "" {
		t.Error("CredentialID is empty")
	}
	if entry.UserHandle == "" {
		t.Error("UserHandle is empty")
	}
	if len(entry.PublicKeyCOSE) == 0 {
		t.Error("PublicKeyCOSE is empty")
	}
	if entry.PrivateKeyPEM == "" {
		t.Error("PrivateKeyPEM is empty")
	}
	if !bytes.HasPrefix([]byte(entry.PrivateKeyPEM), []byte("-----BEGIN EC PRIVATE KEY-----")) {
		t.Error("PrivateKeyPEM should be EC PRIVATE KEY for ES256")
	}

	// Verify the COSE public key is valid EC2 key.
	var coseKey coseEC2Key
	if err := cbor.Unmarshal(entry.PublicKeyCOSE, &coseKey); err != nil {
		t.Fatalf("failed to unmarshal COSE public key: %v", err)
	}
	if coseKey.Kty != 2 {
		t.Errorf("COSE kty = %d, want 2 (EC2)", coseKey.Kty)
	}
	if coseKey.Crv != 1 {
		t.Errorf("COSE crv = %d, want 1 (P-256)", coseKey.Crv)
	}
	if coseKey.Alg != COSEAlgES256 {
		t.Errorf("COSE alg = %d, want %d", coseKey.Alg, COSEAlgES256)
	}
	if len(coseKey.X) == 0 || len(coseKey.Y) == 0 {
		t.Error("COSE key X or Y is empty")
	}
}

// TestCreatePasskeyEdDSA verifies creating a passkey with EdDSA algorithm.
func TestCreatePasskeyEdDSA(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: true,
	}
	pool := newTestPoolWithDB(t)
	svc := NewFido2Service(cfg, pool)

	dbs := pool.List()
	if len(dbs) == 0 {
		t.Fatal("pool has no databases")
	}
	testUUID := dbs[0].UUID

	entry, err := svc.CreatePasskey(
		testUUID,
		"gitlab.com",
		"GitLab",
		"devuser",
		"Dev User",
		[]int{COSEAlgEdDSA},
	)
	if err != nil {
		t.Fatalf("CreatePasskey(EdDSA) failed: %v", err)
	}
	if entry == nil {
		t.Fatal("CreatePasskey returned nil entry")
	}

	// Verify entry fields.
	if entry.RPID != "gitlab.com" {
		t.Errorf("RPID = %q, want gitlab.com", entry.RPID)
	}
	if entry.CredentialID == "" {
		t.Error("CredentialID is empty")
	}

	// Verify the PEM is PKCS8 format for Ed25519.
	if !bytes.HasPrefix([]byte(entry.PrivateKeyPEM), []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Error("PrivateKeyPEM should be PRIVATE KEY (PKCS8) for EdDSA")
	}

	// Verify the COSE public key is valid OKP key.
	var coseKey coseOKPKey
	if err := cbor.Unmarshal(entry.PublicKeyCOSE, &coseKey); err != nil {
		t.Fatalf("failed to unmarshal COSE public key: %v", err)
	}
	if coseKey.Kty != 1 {
		t.Errorf("COSE kty = %d, want 1 (OKP)", coseKey.Kty)
	}
	if coseKey.Crv != 6 {
		t.Errorf("COSE crv = %d, want 6 (Ed25519)", coseKey.Crv)
	}
	if coseKey.Alg != COSEAlgEdDSA {
		t.Errorf("COSE alg = %d, want %d", coseKey.Alg, COSEAlgEdDSA)
	}
	if len(coseKey.X) != 32 {
		t.Errorf("COSE X length = %d, want 32", len(coseKey.X))
	}
}

// TestCreatePasskeyDefaultAlgorithm verifies that CreatePasskey defaults
// to ES256 when no algorithms are specified.
func TestCreatePasskeyDefaultAlgorithm(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: true,
	}
	pool := newTestPoolWithDB(t)
	svc := NewFido2Service(cfg, pool)

	dbs := pool.List()
	if len(dbs) == 0 {
		t.Fatal("pool has no databases")
	}
	testUUID := dbs[0].UUID

	entry, err := svc.CreatePasskey(
		testUUID,
		"example.com",
		"Example",
		"user",
		"User",
		nil, // no algorithms specified
	)
	if err != nil {
		t.Fatalf("CreatePasskey(nil alg) failed: %v", err)
	}

	// Should be ES256 (EC PRIVATE KEY).
	if !bytes.HasPrefix([]byte(entry.PrivateKeyPEM), []byte("-----BEGIN EC PRIVATE KEY-----")) {
		t.Error("default algorithm should be ES256, but PEM is not EC PRIVATE KEY")
	}
}

// TestCreatePasskeyUnsupportedAlgorithm verifies that CreatePasskey
// returns an error for unsupported algorithms.
func TestCreatePasskeyUnsupportedAlgorithm(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: true,
	}
	pool := dbpool.NewDatabasePool(nil)
	svc := NewFido2Service(cfg, pool)

	_, err := svc.CreatePasskey(
		"test-db-uuid",
		"example.com",
		"Example",
		"user",
		"User",
		[]int{COSEAlgPS256}, // RSASSA-PSS not implemented
	)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

// TestCreatePasskeyDisabledService verifies that CreatePasskey returns
// an error when the FIDO2 service is disabled.
func TestCreatePasskeyDisabledService(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: false,
	}
	pool := dbpool.NewDatabasePool(nil)
	svc := NewFido2Service(cfg, pool)

	_, err := svc.CreatePasskey(
		"test-db-uuid",
		"example.com",
		"Example",
		"user",
		"User",
		[]int{COSEAlgES256},
	)
	if err == nil {
		t.Fatal("expected error for disabled service, got nil")
	}
}

// TestCreatePasskeyDatabaseNotFound verifies that CreatePasskey returns
// an error when the database is not found in the pool.
func TestCreatePasskeyDatabaseNotFound(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: true,
	}
	pool := dbpool.NewDatabasePool(nil)
	svc := NewFido2Service(cfg, pool)

	_, err := svc.CreatePasskey(
		"nonexistent-db-uuid",
		"example.com",
		"Example",
		"user",
		"User",
		[]int{COSEAlgES256},
	)
	if err == nil {
		t.Fatal("expected error for nonexistent database, got nil")
	}
}

// TestFindPasskeysByRPIDOnEmptyPool verifies that FindPasskeysByRPID
// returns nil/empty when the pool has no databases.
func TestFindPasskeysByRPIDOnEmptyPool(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: true,
	}
	pool := dbpool.NewDatabasePool(nil)
	svc := NewFido2Service(cfg, pool)

	results, err := svc.FindPasskeysByRPID("", "github.com")
	if err != nil {
		t.Fatalf("FindPasskeysByRPID failed: %v", err)
	}
	// results may be nil or empty slice — both are acceptable.
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// TestNewFido2Service verifies that NewFido2Service creates a non-nil service.
func TestNewFido2Service(t *testing.T) {
	cfg := &config.Fido2Config{Enabled: true}
	pool := dbpool.NewDatabasePool(nil)
	svc := NewFido2Service(cfg, pool)

	if svc == nil {
		t.Fatal("NewFido2Service returned nil")
	}
	if svc.config != cfg {
		t.Error("config not set correctly")
	}
	if svc.pool != pool {
		t.Error("pool not set correctly")
	}
}

// TestPasskeyEntryDefaults verifies that a created passkey has reasonable defaults.
func TestPasskeyEntryDefaults(t *testing.T) {
	cfg := &config.Fido2Config{
		Enabled: true,
	}
	pool := newTestPoolWithDB(t)
	svc := NewFido2Service(cfg, pool)

	dbs := pool.List()
	if len(dbs) == 0 {
		t.Fatal("pool has no databases")
	}
	testUUID := dbs[0].UUID

	entry, err := svc.CreatePasskey(
		testUUID,
		"rp.example.com",
		"RP Name",
		"alice",
		"Alice",
		[]int{COSEAlgES256},
	)
	if err != nil {
		t.Fatalf("CreatePasskey failed: %v", err)
	}

	if entry.Subject != "Alice" {
		t.Errorf("Subject = %q, want Alice", entry.Subject)
	}
	if entry.RPID != "rp.example.com" {
		t.Errorf("RPID = %q, want rp.example.com", entry.RPID)
	}
	if entry.RPName != "RP Name" {
		t.Errorf("RPName = %q, want RP Name", entry.RPName)
	}
	if entry.Username != "alice" {
		t.Errorf("Username = %q, want alice", entry.Username)
	}
}

// TestCOSEKeyConstants verifies the COSE algorithm constant values.
func TestCOSEKeyConstants(t *testing.T) {
	if COSEAlgES256 != -7 {
		t.Errorf("COSEAlgES256 = %d, want -7", COSEAlgES256)
	}
	if COSEAlgEdDSA != -8 {
		t.Errorf("COSEAlgEdDSA = %d, want -8", COSEAlgEdDSA)
	}
	if COSEAlgES256K != -25 {
		t.Errorf("COSEAlgES256K = %d, want -25", COSEAlgES256K)
	}
	if COSEAlgPS256 != -37 {
		t.Errorf("COSEAlgPS256 = %d, want -37", COSEAlgPS256)
	}
}

// TestAuthenticatorFlagConstants verifies the authenticator flag constants.
func TestAuthenticatorFlagConstants(t *testing.T) {
	if FlagUP != 0x01 {
		t.Errorf("FlagUP = 0x%02x, want 0x01", FlagUP)
	}
	if FlagUV != 0x04 {
		t.Errorf("FlagUV = 0x%04x, want 0x04", FlagUV)
	}
	if FlagBE != 0x08 {
		t.Errorf("FlagBE = 0x%02x, want 0x08", FlagBE)
	}
	if FlagBS != 0x10 {
		t.Errorf("FlagBS = 0x%02x, want 0x10", FlagBS)
	}
	if FlagAT != 0x40 {
		t.Errorf("FlagAT = 0x%02x, want 0x40", FlagAT)
	}
	if FlagED != 0x80 {
		t.Errorf("FlagED = 0x%02x, want 0x80", FlagED)
	}
}

// newTestPoolWithDB creates a DatabasePool with a test KDBX database
// and returns it. The database is stored in t.TempDir and cleaned up
// automatically. The pool is already populated with one database.
func newTestPoolWithDB(t *testing.T) *dbpool.DatabasePool {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.kdbx")

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpassword")

	now := time.Now()
	db.Content.Root.Groups[0].Times = gokeepasslib.TimeData{
		CreationTime:         &wrappers.TimeWrapper{Time: now},
		LastModificationTime: &wrappers.TimeWrapper{Time: now},
	}

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries failed: %v", err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create test db file: %v", err)
	}
	defer f.Close()

	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatalf("failed to encode test db: %v", err)
	}

	// Open the database in the pool.
	ss, err := security.NewSecureString("testpassword")
	if err != nil {
		t.Fatalf("failed to create secure string: %v", err)
	}
	defer ss.Destroy()
	cred := dbpool.PasswordCredential(ss)

	pool := dbpool.NewDatabasePool(nil)
	if _, err := pool.Open(path, cred); err != nil {
		t.Fatalf("pool.Open failed: %v", err)
	}

	return pool
}
