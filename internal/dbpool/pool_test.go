//go:build linux

package dbpool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/metalgrid/kpxcd/internal/security"
)

// createTestKDBX creates a minimal KDBX database file with a password
// and returns the file path. The caller should clean up the file.
func createTestKDBX(t *testing.T, dir, filename, password string, entries []gokeepasslib.Entry) string {
	t.Helper()

	path := filepath.Join(dir, filename)

	// Use NewDatabase which properly initializes all headers.
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	// Replace the root group entries with our test entries.
	groupUUID := gokeepasslib.NewUUID()
	db.Content.Root.Groups[0].UUID = groupUUID
	db.Content.Root.Groups[0].Name = "TestGroup"
	db.Content.Root.Groups[0].Entries = entries

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("failed to lock protected entries: %v", err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create test db file: %v", err)
	}
	defer f.Close()

	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatalf("failed to encode test db: %v", err)
	}

	return path
}

// TestNewDatabasePoolCreatesEmptyPool verifies that NewDatabasePool
// returns a non-nil pool with an empty internal map.
func TestNewDatabasePoolCreatesEmptyPool(t *testing.T) {
	eventCh := make(chan Event, 10)
	pool := NewDatabasePool(eventCh)

	if pool == nil {
		t.Fatal("NewDatabasePool returned nil")
	}
	if len(pool.List()) != 0 {
		t.Errorf("expected empty pool, got %d databases", len(pool.List()))
	}
}

// TestListReturnsEmptyOnNewPool verifies that List returns an empty
// slice for a newly created pool.
func TestListReturnsEmptyOnNewPool(t *testing.T) {
	pool := NewDatabasePool(nil)

	dbs := pool.List()
	if dbs == nil {
		t.Fatal("List returned nil")
	}
	if len(dbs) != 0 {
		t.Errorf("expected 0 databases, got %d", len(dbs))
	}
}

// TestCloseOnEmptyPool verifies that Close on an empty pool returns nil.
func TestCloseOnEmptyPool(t *testing.T) {
	pool := NewDatabasePool(nil)

	if err := pool.Close(); err != nil {
		t.Errorf("Close on empty pool returned error: %v", err)
	}
}

// TestGetReturnsErrorForNonexistentUUID verifies that Get returns an
// error when asked for a UUID that does not exist in the pool.
func TestGetReturnsErrorForNonexistentUUID(t *testing.T) {
	pool := NewDatabasePool(nil)

	_, err := pool.Get("nonexistent-uuid")
	if err == nil {
		t.Fatal("expected error for nonexistent UUID, got nil")
	}
	if got := err.Error(); got == "" {
		t.Error("expected non-empty error message")
	}
}

// TestLockAllOnEmptyPool verifies that LockAll on an empty pool returns nil.
func TestLockAllOnEmptyPool(t *testing.T) {
	pool := NewDatabasePool(nil)

	if err := pool.LockAll(); err != nil {
		t.Errorf("LockAll on empty pool returned error: %v", err)
	}
}

// TestOpenAndReadEntries verifies that a test KDBX database can be created,
// opened by the pool, and entries can be read from it.
func TestOpenAndReadEntries(t *testing.T) {
	dir := t.TempDir()

	testEntries := []gokeepasslib.Entry{
		{
			UUID: gokeepasslib.NewUUID(),
			Values: []gokeepasslib.ValueData{
				{Key: "Title", Value: gokeepasslib.V{Content: "Test Entry 1"}},
				{Key: "UserName", Value: gokeepasslib.V{Content: "testuser"}},
				{Key: "Password", Value: gokeepasslib.V{Content: "s3cr3t", Protected: wrappers.BoolWrapper{Bool: true}}},
				{Key: "URL", Value: gokeepasslib.V{Content: "https://example.com"}},
			},
		},
		{
			UUID: gokeepasslib.NewUUID(),
			Values: []gokeepasslib.ValueData{
				{Key: "Title", Value: gokeepasslib.V{Content: "Test Entry 2"}},
				{Key: "UserName", Value: gokeepasslib.V{Content: "admin"}},
				{Key: "Password", Value: gokeepasslib.V{Content: "p4ssw0rd", Protected: wrappers.BoolWrapper{Bool: true}}},
			},
		},
	}

	dbPath := createTestKDBX(t, dir, "test.kdbx", "testpassword", testEntries)

	// Create password credential.
	ss, err := security.NewSecureString("testpassword")
	if err != nil {
		t.Fatalf("failed to create secure string: %v", err)
	}
	defer ss.Destroy()
	cred := PasswordCredential(ss)

	eventCh := make(chan Event, 10)
	pool := NewDatabasePool(eventCh)
	defer pool.Close()

	// Open the database.
	uuid, err := pool.Open(dbPath, cred)
	if err != nil {
		t.Fatalf("pool.Open failed: %v", err)
	}
	if uuid == "" {
		t.Fatal("Open returned empty UUID")
	}

	// Verify List returns one database.
	dbs := pool.List()
	if len(dbs) != 1 {
		t.Fatalf("expected 1 database in pool, got %d", len(dbs))
	}

	// Verify Get returns the database.
	odb, err := pool.Get(uuid)
	if err != nil {
		t.Fatalf("pool.Get failed: %v", err)
	}
	if odb.UUID != uuid {
		t.Errorf("expected UUID %q, got %q", uuid, odb.UUID)
	}
	if odb.Locked {
		t.Error("database should not be locked after open")
	}

	// Verify entries can be read.
	entries := odb.RootEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Check first entry.
	if got := entries[0].GetTitle(); got != "Test Entry 1" {
		t.Errorf("entry[0] title = %q, want %q", got, "Test Entry 1")
	}
	if got := entries[0].GetContent("UserName"); got != "testuser" {
		t.Errorf("entry[0] username = %q, want %q", got, "testuser")
	}
	if got := entries[0].GetContent("URL"); got != "https://example.com" {
		t.Errorf("entry[0] URL = %q, want %q", got, "https://example.com")
	}

	// Check second entry.
	if got := entries[1].GetTitle(); got != "Test Entry 2" {
		t.Errorf("entry[1] title = %q, want %q", got, "Test Entry 2")
	}
}

// TestOpenWrongPassword verifies that opening a database with the wrong
// password returns an error.
func TestOpenWrongPassword(t *testing.T) {
	dir := t.TempDir()

	entries := []gokeepasslib.Entry{
		{
			UUID: gokeepasslib.NewUUID(),
			Values: []gokeepasslib.ValueData{
				{Key: "Title", Value: gokeepasslib.V{Content: "Secret"}},
			},
		},
	}
	dbPath := createTestKDBX(t, dir, "wrong.kdbx", "correctpassword", entries)

	// Try to open with wrong password.
	wrongSS, err := security.NewSecureString("wrongpassword")
	if err != nil {
		t.Fatalf("failed to create secure string: %v", err)
	}
	defer wrongSS.Destroy()
	cred := PasswordCredential(wrongSS)

	pool := NewDatabasePool(nil)
	defer pool.Close()

	_, err = pool.Open(dbPath, cred)
	if err == nil {
		t.Fatal("expected error when opening with wrong password, got nil")
	}
}

// TestLockAndUnlockCycle verifies that a database can be locked and
// that it correctly transitions to the locked state.
func TestLockAndUnlockCycle(t *testing.T) {
	dir := t.TempDir()

	entries := []gokeepasslib.Entry{
		{
			UUID: gokeepasslib.NewUUID(),
			Values: []gokeepasslib.ValueData{
				{Key: "Title", Value: gokeepasslib.V{Content: "LockTest"}},
			},
		},
	}
	dbPath := createTestKDBX(t, dir, "lock.kdbx", "lockpassword", entries)

	ss, err := security.NewSecureString("lockpassword")
	if err != nil {
		t.Fatalf("failed to create secure string: %v", err)
	}
	defer ss.Destroy()
	cred := PasswordCredential(ss)

	eventCh := make(chan Event, 10)
	pool := NewDatabasePool(eventCh)
	defer pool.Close()

	uuid, err := pool.Open(dbPath, cred)
	if err != nil {
		t.Fatalf("pool.Open failed: %v", err)
	}

	// Verify unlocked state.
	odb, err := pool.Get(uuid)
	if err != nil {
		t.Fatalf("pool.Get failed: %v", err)
	}
	if odb.Locked {
		t.Error("database should be unlocked after open")
	}
	if len(odb.RootEntries()) == 0 {
		t.Error("should have entries before lock")
	}

	// Lock the database.
	if err := pool.Lock(uuid); err != nil {
		t.Fatalf("pool.Lock failed: %v", err)
	}

	// Verify locked state.
	odb, err = pool.Get(uuid)
	if err != nil {
		t.Fatalf("pool.Get after lock failed: %v", err)
	}
	if !odb.Locked {
		t.Error("database should be locked after Lock()")
	}

	// Verify entries are cleared.
	entries = odb.RootEntries()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after lock, got %d", len(entries))
	}

	// Verify lock event was sent.
	// First, consume the unlock event from Open.
	select {
	case ev := <-eventCh:
		if ev.Type != EventDatabaseUnlocked {
			t.Errorf("expected EventDatabaseUnlocked, got %d", ev.Type)
		}
	default:
		t.Error("expected unlock event on channel")
	}

	// Now check for the lock event.
	select {
	case ev := <-eventCh:
		if ev.Type != EventDatabaseLocked {
			t.Errorf("expected EventDatabaseLocked, got %d", ev.Type)
		}
		if ev.UUID != uuid {
			t.Errorf("event UUID = %q, want %q", ev.UUID, uuid)
		}
	default:
		t.Error("expected lock event on channel")
	}
}
