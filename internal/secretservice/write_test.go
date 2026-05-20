//go:build linux

package secretservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/user/kpxcd/internal/dbpool"
	"github.com/user/kpxcd/internal/security"
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

func TestCreateItemPersistsToKDBX(t *testing.T) {
	path := createWritableTestDB(t, t.TempDir(), "password")
	pool, odb := openWritableTestDB(t, path, "password")

	svc := NewSecretService(pool)
	sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/test")
	svc.sessions[sessionPath] = NewPlainSession(nil, sessionPath)
	coll := newCollection(nil, svc, odb)

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
