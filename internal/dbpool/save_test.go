//go:build linux

package dbpool

import (
	"os"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/metalgrid/kpxcd/internal/security"
)

func TestUpdateAndSavePersistsMutation(t *testing.T) {
	dir := t.TempDir()
	entries := []gokeepasslib.Entry{{
		UUID: gokeepasslib.NewUUID(),
		Values: []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: "Saved Entry"}},
			{Key: "Password", Value: gokeepasslib.V{Content: "old", Protected: wrappers.BoolWrapper{Bool: true}}},
		},
	}}
	path := createTestKDBX(t, dir, "save.kdbx", "password", entries)

	ss, err := security.NewSecureString("password")
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Destroy()

	pool := NewDatabasePool(nil)
	defer pool.Close()
	uuid, err := pool.Open(path, PasswordCredential(ss))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	odb, err := pool.Get(uuid)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if err := odb.UpdateAndSave(func(db *gokeepasslib.Database) error {
		db.Content.Root.Groups[0].Entries[0].Values[1].Value.Content = "new"
		return nil
	}); err != nil {
		t.Fatalf("UpdateAndSave failed: %v", err)
	}

	pool2 := NewDatabasePool(nil)
	defer pool2.Close()
	ss2, err := security.NewSecureString("password")
	if err != nil {
		t.Fatal(err)
	}
	defer ss2.Destroy()
	uuid2, err := pool2.Open(path, PasswordCredential(ss2))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	odb2, _ := pool2.Get(uuid2)
	got := odb2.RootEntries()[0].GetPassword()
	if got != "new" {
		t.Fatalf("password after reopen = %q, want new", got)
	}
}

func TestUpdateAndSaveRefusesExternalChange(t *testing.T) {
	dir := t.TempDir()
	path := createTestKDBX(t, dir, "conflict.kdbx", "password", nil)

	ss, err := security.NewSecureString("password")
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Destroy()

	pool := NewDatabasePool(nil)
	defer pool.Close()
	uuid, err := pool.Open(path, PasswordCredential(ss))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	odb, err := pool.Get(uuid)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("external")); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	err = odb.UpdateAndSave(func(db *gokeepasslib.Database) error {
		db.Content.Root.Groups[0].Name = "mutated"
		return nil
	})
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
}
