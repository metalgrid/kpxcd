//go:build linux

package dbpool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metalgrid/kpxcd/internal/security"
)

func TestCreateDatabaseCreatesSecureKDBX(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kpxcd", "default.kdbx")
	if err := CreateDatabase(path, "password"); err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 0600", got)
	}
	ss, err := security.NewSecureString("password")
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Destroy()
	pool := NewDatabasePool(nil)
	defer pool.Close()
	if _, err := pool.Open(path, PasswordCredential(ss)); err != nil {
		t.Fatalf("open created db failed: %v", err)
	}
}

func TestCreateDatabaseDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "default.kdbx")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateDatabase(path, "password"); err == nil {
		t.Fatal("expected existing database error")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatal("existing file was modified")
	}
}
