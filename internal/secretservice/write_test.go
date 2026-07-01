//go:build linux

package secretservice

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/security"
)

func createWritableTestDB(t *testing.T, dir, password string) string {
	t.Helper()
	path := filepath.Join(dir, "writable.kdbx")
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content.Root.Groups[0].Name = "Root"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	return path
}

func openWritableTestDB(t *testing.T, path, password string) (*dbpool.DatabasePool, *dbpool.OpenDatabase) {
	t.Helper()
	ss, err := security.NewSecureString(password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ss.Destroy)
	pool := dbpool.NewDatabasePool(nil)
	t.Cleanup(func() { _ = pool.Close() })
	uuid, err := pool.Open(path, dbpool.PasswordCredential(ss))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	odb, err := pool.Get(uuid)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	return pool, odb
}

func setupCollection(t *testing.T) (string, *Collection, *dbpool.OpenDatabase, dbus.ObjectPath) {
	t.Helper()
	path := createWritableTestDB(t, t.TempDir(), "password")
	pool, odb := openWritableTestDB(t, path, "password")

	svc := NewSecretService(pool)
	sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/test")
	svc.sessions[sessionPath] = NewPlainSession(nil, sessionPath)
	coll := newCollection(nil, svc, odb)
	return path, coll, odb, sessionPath
}

func TestCreateItemPersistsToKDBX(t *testing.T) {
	path, coll, _, sessionPath := setupCollection(t)

	props := map[string]dbus.Variant{
		InterfaceItem + ".Label":      dbus.MakeVariant("Chrome Safe Storage"),
		InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "chrome", "xdg:schema": "chrome_libsecret_os_crypt_password_v2"}),
	}
	secret := DBusSecret{Session: sessionPath, Value: []byte("super-secret"), ContentType: "text/plain"}
	itemPath, prompt, dbusErr := coll.CreateItem(props, secret, false)
	if dbusErr != nil {
		t.Fatalf("CreateItem failed: %v", dbusErr)
	}
	if itemPath == "/" || prompt != "/" {
		t.Fatalf("unexpected CreateItem result: item=%s prompt=%s", itemPath, prompt)
	}

	_, reopened := openWritableTestDB(t, path, "password")
	entries := reopened.RootEntries()
	var found *gokeepasslib.Entry
	for i := range entries {
		if entries[i].GetTitle() == "Chrome Safe Storage" {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("created item not found after reopen")
	}
	if got := found.GetPassword(); got != "super-secret" {
		t.Fatalf("password = %q, want super-secret", got)
	}
	if got := found.GetContent("application"); got != "chrome" {
		t.Fatalf("application attr = %q, want chrome", got)
	}
}

func TestSetSecretUpdatesPassword(t *testing.T) {
	path, coll, _, sessionPath := setupCollection(t)

	props := map[string]dbus.Variant{
		InterfaceItem + ".Label":      dbus.MakeVariant("Update Test"),
		InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "test"}),
	}
	itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("old-password")}, false)
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}

	item := newItem(nil, coll, findEntryByItemPath(t, coll, itemPath))
	if derr := item.SetSecret(DBusSecret{Session: sessionPath, Value: []byte("new-password")}); derr != nil {
		t.Fatalf("SetSecret failed: %v", derr)
	}

	_, reopened := openWritableTestDB(t, path, "password")
	entries := reopened.RootEntries()
	var found *gokeepasslib.Entry
	for i := range entries {
		if entries[i].GetTitle() == "Update Test" {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("updated item not found after reopen")
	}
	if got := found.GetPassword(); got != "new-password" {
		t.Fatalf("password = %q, want new-password", got)
	}
}

func TestSetSecretDoesNotReturnStalePassword(t *testing.T) {
	_, coll, _, sessionPath := setupCollection(t)

	props := map[string]dbus.Variant{
		InterfaceItem + ".Label":      dbus.MakeVariant("Stale Test"),
		InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "stale"}),
	}
	itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("old-password")}, false)
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}

	item := newItem(nil, coll, findEntryByItemPath(t, coll, itemPath))
	if derr := item.SetSecret(DBusSecret{Session: sessionPath, Value: []byte("new-password")}); derr != nil {
		t.Fatalf("SetSecret failed: %v", derr)
	}

	secret, derr := item.GetSecret("", sessionPath)
	if derr != nil {
		t.Fatalf("GetSecret failed: %v", derr)
	}
	got := string(secret.Value)
	if got != "new-password" {
		t.Fatalf("GetSecret returned stale password %q, want new-password", got)
	}
}

func TestCreateItemReplaceUpdatesExisting(t *testing.T) {
	path, coll, _, sessionPath := setupCollection(t)

	props := map[string]dbus.Variant{
		InterfaceItem + ".Label":      dbus.MakeVariant("Replace Test"),
		InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "replace", "user": "alice"}),
	}
	itemPath1, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("secret-one")}, false)
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}

	// Store the original UUID to verify it is the same entry after replace.
	originalEntry := findEntryByItemPath(t, coll, itemPath1)
	originalUUID := fmt.Sprintf("%x", originalEntry.UUID[:])

	props[InterfaceItem+".Label"] = dbus.MakeVariant("Replace Test Updated")
	itemPath2, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("secret-two")}, true)
	if err != nil {
		t.Fatalf("CreateItem replace failed: %v", err)
	}
	if itemPath1 != itemPath2 {
		t.Fatalf("replace changed item path: %s -> %s", itemPath1, itemPath2)
	}

	_, reopened := openWritableTestDB(t, path, "password")
	entries := reopened.RootEntries()
	count := 0
	var found *gokeepasslib.Entry
	for i := range entries {
		uuid := fmt.Sprintf("%x", entries[i].UUID[:])
		if uuid == originalUUID {
			count++
			found = &entries[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 entry with original UUID, found %d", count)
	}
	if found.GetTitle() != "Replace Test Updated" {
		t.Fatalf("title = %q, want Replace Test Updated", found.GetTitle())
	}
	if found.GetPassword() != "secret-two" {
		t.Fatalf("password = %q, want secret-two", found.GetPassword())
	}
}

func TestCreateItemReplacePreservesHistory(t *testing.T) {
	path, coll, _, sessionPath := setupCollection(t)

	props := map[string]dbus.Variant{
		InterfaceItem + ".Label":      dbus.MakeVariant("History Test"),
		InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "history"}),
	}
	itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("first-password")}, false)
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}

	_, _, err = coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("second-password")}, true)
	if err != nil {
		t.Fatalf("CreateItem replace failed: %v", err)
	}

	_, reopened := openWritableTestDB(t, path, "password")
	entry := findEntryByItemPathOnDB(t, reopened, itemPath)
	if entry == nil {
		t.Fatal("entry not found after reopen")
	}
	if len(entry.Histories) == 0 || len(entry.Histories[0].Entries) == 0 {
		t.Fatal("expected history entry after replace")
	}
	if entry.Histories[0].Entries[0].GetPassword() != "first-password" {
		t.Fatalf("history password = %q, want first-password", entry.Histories[0].Entries[0].GetPassword())
	}
}

func TestDeleteItemRemovesEntry(t *testing.T) {
	path, coll, _, sessionPath := setupCollection(t)

	props := map[string]dbus.Variant{
		InterfaceItem + ".Label":      dbus.MakeVariant("Delete Test"),
		InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "delete"}),
	}
	itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("delete-me")}, false)
	if err != nil {
		t.Fatalf("CreateItem failed: %v", err)
	}

	item := newItem(nil, coll, findEntryByItemPath(t, coll, itemPath))
	if _, derr := item.Delete(); derr != nil {
		t.Fatalf("Delete failed: %v", derr)
	}

	_, reopened := openWritableTestDB(t, path, "password")
	entries := reopened.RootEntries()
	for i := range entries {
		if entries[i].GetTitle() == "Delete Test" {
			t.Fatal("deleted item still present after reopen")
		}
	}
}

func findEntryByItemPath(t *testing.T, coll *Collection, itemPath dbus.ObjectPath) gokeepasslib.Entry {
	t.Helper()
	coll.db.RLock()
	defer coll.db.RUnlock()
	uuid := pathUUID(itemPath)
	entry := findEntryPtrByUUID(coll.db.Db.Content.Root.Groups, uuid)
	if entry == nil {
		t.Fatalf("entry not found for path %s", itemPath)
	}
	return *entry
}

func findEntryByItemPathOnDB(t *testing.T, odb *dbpool.OpenDatabase, itemPath dbus.ObjectPath) *gokeepasslib.Entry {
	t.Helper()
	odb.RLock()
	defer odb.RUnlock()
	return findEntryPtrByUUID(odb.Db.Content.Root.Groups, pathUUID(itemPath))
}

func pathUUID(itemPath dbus.ObjectPath) string {
	s := string(itemPath)
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		return s[idx+1:]
	}
	return s
}
