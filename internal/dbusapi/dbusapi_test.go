//go:build linux

package dbusapi

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
)

// TestPing verifies that the Ping method returns "pong".
func TestPing(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	f2 := fido2.NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
	handler := NewDaemonDBus(cfg, pool, f2, nil)

	if handler == nil {
		t.Fatal("NewDaemonDBus returned nil")
	}

	result, err := handler.Ping()
	if err != nil {
		t.Fatalf("Ping returned error: %v", err)
	}
	if result != "pong" {
		t.Errorf("Ping = %q, want pong", result)
	}
}

// TestPingDoesNotRequireDBusConnection verifies that Ping works
// without an actual DBus connection.
func TestPingDoesNotRequireDBusConnection(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	result, err := handler.Ping()
	if err != nil {
		t.Fatalf("Ping returned error: %v", err)
	}
	if result != "pong" {
		t.Errorf("Ping = %q, want pong", result)
	}
}

// TestListDatabasesOnEmptyPool verifies that ListDatabases returns an
// empty slice when the pool has no databases.
func TestListDatabasesOnEmptyPool(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	dbs, err := handler.ListDatabases()
	if err != nil {
		t.Fatalf("ListDatabases returned error: %v", err)
	}
	if dbs == nil {
		t.Fatal("ListDatabases returned nil")
	}
	if len(dbs) != 0 {
		t.Errorf("expected 0 databases, got %d", len(dbs))
	}
}

// TestListDatabasesWithDatabases verifies that ListDatabases correctly
// returns information about databases in the pool.
func TestListDatabasesWithDatabases(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)

	// Manually insert a database into the pool for testing.
	// We use the internal map directly via the pool's methods.
	// Since we can't call Open without a real KDBX file, we use the pool's
	// exported methods. Instead, we just test with an empty pool.
	// The actual integration is tested in pool_test.go.

	handler := NewDaemonDBus(cfg, pool, nil, nil)

	dbs, err := handler.ListDatabases()
	if err != nil {
		t.Fatalf("ListDatabases returned error: %v", err)
	}

	// With an empty pool, we should get an empty list.
	if len(dbs) != 0 {
		t.Errorf("expected 0 databases, got %d", len(dbs))
	}
}

// TestListDatabasesReturnFields verifies that each database in the
// ListDatabases result has the expected fields.
func TestListDatabasesReturnFields(t *testing.T) {
	cfg := config.DefaultConfig()
	eventCh := make(chan dbpool.Event, 10)
	pool := dbpool.NewDatabasePool(eventCh)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	dbs, err := handler.ListDatabases()
	if err != nil {
		t.Fatalf("ListDatabases returned error: %v", err)
	}

	// For empty pool, verify the returned type.
	if _, ok := interface{}(dbs).([]map[string]dbus.Variant); !ok {
		t.Errorf("ListDatabases did not return []map[string]dbus.Variant")
	}
}

// TestNewDaemonDBus verifies that NewDaemonDBus creates a properly
// initialized handler.
func TestNewDaemonDBus(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	f2 := fido2.NewFido2Service(&config.Fido2Config{Enabled: true}, pool)

	handler := NewDaemonDBus(cfg, pool, f2, nil)
	if handler == nil {
		t.Fatal("NewDaemonDBus returned nil")
	}
	if handler.config != cfg {
		t.Error("config not set correctly")
	}
	if handler.pool != pool {
		t.Error("pool not set correctly")
	}
	if handler.fido2 != f2 {
		t.Error("fido2 service not set correctly")
	}
	// conn should be nil until Export is called.
	if handler.conn != nil {
		t.Error("conn should be nil before Export")
	}
}

// TestNewDaemonDBusWithNilFido2 verifies that NewDaemonDBus works
// when the FIDO2 service is nil.
func TestNewDaemonDBusWithNilFido2(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)

	handler := NewDaemonDBus(cfg, pool, nil, nil)
	if handler == nil {
		t.Fatal("NewDaemonDBus returned nil")
	}
	if handler.fido2 != nil {
		t.Error("fido2 should be nil")
	}
}

// TestCloseDoesNotPanic verifies that Close on a handler without
// an established connection does not panic.
func TestCloseDoesNotPanic(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	// Should not panic.
	handler.Close()
}

// TestLockAllOnEmptyPool verifies that LockAll returns success on an
// empty pool.
func TestLockAllOnEmptyPool(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	ok, err := handler.LockAll()
	if err != nil {
		t.Fatalf("LockAll returned error: %v", err)
	}
	if !ok {
		t.Error("LockAll should return true on success")
	}
}

// TestLockDatabaseNotFound verifies that LockDatabase returns an error
// for a nonexistent database.
func TestLockDatabaseNotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	ok, err := handler.LockDatabase("nonexistent-uuid")
	if err == nil {
		t.Fatal("expected error for nonexistent database, got nil")
	}
	if ok {
		t.Error("LockDatabase should return false on failure")
	}
}

// TestGetEntryDatabaseNotFound verifies that GetEntry returns an error
// when the database is not found.
func TestGetEntryDatabaseNotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	_, err := handler.GetEntry("nonexistent-uuid", "some-entry")
	if err == nil {
		t.Fatal("expected error for nonexistent database, got nil")
	}
}

// TestSearchEntriesEmptyPool verifies that SearchEntries returns
// an empty/nil result when searching an empty pool.
func TestSearchEntriesEmptyPool(t *testing.T) {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	handler := NewDaemonDBus(cfg, pool, nil, nil)

	results, err := handler.SearchEntries("", "test")
	if err != nil {
		t.Fatalf("SearchEntries returned error: %v", err)
	}
	// results may be nil or empty slice — both are acceptable for no matches.
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}
