//go:build linux

package secretservice

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/tobischo/gokeepasslib/v3"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/security"
)

func createWritableTestDB(dir, password string) string {
	path := filepath.Join(dir, "writable.kdbx")
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content.Root.Groups[0].Name = "Root"
	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	Expect(gokeepasslib.NewEncoder(f).Encode(db)).To(Succeed())
	return path
}

func openWritableTestDB(path, password string) (*dbpool.DatabasePool, *dbpool.OpenDatabase) {
	ss, err := security.NewSecureString(password)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(ss.Destroy)
	pool := dbpool.NewDatabasePool(nil)
	DeferCleanup(func() { _ = pool.Close() })
	uuid, err := pool.Open(path, dbpool.PasswordCredential(ss))
	Expect(err).NotTo(HaveOccurred())
	odb, err := pool.Get(uuid)
	Expect(err).NotTo(HaveOccurred())
	return pool, odb
}

func setupCollection() (string, *Collection, *dbpool.OpenDatabase, dbus.ObjectPath) {
	path := createWritableTestDB(GinkgoT().TempDir(), "password")
	pool, odb := openWritableTestDB(path, "password")

	svc := NewSecretService(pool)
	sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/test")
	svc.sessions[sessionPath] = NewPlainSession(nil, sessionPath)
	coll := newCollection(nil, svc, odb)
	return path, coll, odb, sessionPath
}

var _ = Describe("CreateItem", func() {
	It("persists the item to the KDBX file", func() {
		path, coll, _, sessionPath := setupCollection()

		props := map[string]dbus.Variant{
			InterfaceItem + ".Label":      dbus.MakeVariant("Chrome Safe Storage"),
			InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "chrome", "xdg:schema": "chrome_libsecret_os_crypt_password_v2"}),
		}
		secret := DBusSecret{Session: sessionPath, Value: []byte("super-secret"), ContentType: "text/plain"}
		itemPath, prompt, dbusErr := coll.CreateItem(props, secret, false)
		Expect(dbusErr).NotTo(HaveOccurred())
		Expect(itemPath).NotTo(Equal(dbus.ObjectPath("/")))
		Expect(prompt).To(Equal(dbus.ObjectPath("/")))

		_, reopened := openWritableTestDB(path, "password")
		entries := reopened.RootEntries()
		var found *gokeepasslib.Entry
		for i := range entries {
			if entries[i].GetTitle() == "Chrome Safe Storage" {
				found = &entries[i]
				break
			}
		}
		Expect(found).NotTo(BeNil(), "created item not found after reopen")
		Expect(found.GetPassword()).To(Equal("super-secret"))
		Expect(found.GetContent("application")).To(Equal("chrome"))
	})

	It("preserves client lookup attributes", func() {
		path, coll, _, sessionPath := setupCollection()
		lookupAttrs := map[string]string{
			"service":     "tabularis",
			"username":    "7393e7fe-4d62-453d-8606-6de6fc6c42d0:db",
			"target":      "default",
			"application": "rust-keyring",
		}
		props := map[string]dbus.Variant{
			InterfaceItem + ".Label":      dbus.MakeVariant("Tabularis database password"),
			InterfaceItem + ".Attributes": dbus.MakeVariant(lookupAttrs),
		}
		_, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("secret")}, false)
		Expect(err).NotTo(HaveOccurred())

		pool, reopened := openWritableTestDB(path, "password")
		entries := reopened.RootEntries()
		var found *gokeepasslib.Entry
		for i := range entries {
			if entries[i].GetTitle() == "Tabularis database password" {
				found = &entries[i]
				break
			}
		}
		Expect(found).NotTo(BeNil(), "created item not found after reopen")
		Expect(found.GetContent("username")).To(Equal(lookupAttrs["username"]))
		Expect(found.GetContent("UserName")).To(Equal(""), "client username was rewritten into UserName")

		reopenedCollection := newCollection(nil, NewSecretService(pool), reopened)
		matches, dbusErr := reopenedCollection.SearchItems(map[string]string{
			"service":  lookupAttrs["service"],
			"username": lookupAttrs["username"],
			"target":   lookupAttrs["target"],
		})
		Expect(dbusErr).NotTo(HaveOccurred())
		Expect(matches).To(HaveLen(1), "SearchItems must find the item after reopen")
	})

	It("writes new items into the exposed group", func() {
		path, coll, odb, sessionPath := setupCollection()
		coll.svc.UpdateDatabaseConfigs([]config.DatabaseConfig{{Path: odb.Path, SecretServiceExposeGroup: "Allowed"}})
		Expect(odb.UpdateAndSave(func(db *gokeepasslib.Database) error {
			db.Content.Root.Groups[0].Groups = append(db.Content.Root.Groups[0].Groups, gokeepasslib.Group{Name: "Allowed"})
			return nil
		})).To(Succeed())

		props := map[string]dbus.Variant{
			InterfaceItem + ".Label":      dbus.MakeVariant("Scoped Item"),
			InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "test"}),
		}
		_, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("secret")}, false)
		Expect(err).NotTo(HaveOccurred())

		_, reopened := openWritableTestDB(path, "password")
		groups := reopened.Db.Content.Root.Groups[0].Groups
		Expect(groups).To(HaveLen(1))
		Expect(groups[0].Name).To(Equal("Allowed"))
		Expect(groups[0].Entries).To(HaveLen(1))
		Expect(groups[0].Entries[0].GetTitle()).To(Equal("Scoped Item"))
	})

	Context("with replace enabled", func() {
		It("updates the existing entry in place", func() {
			path, coll, _, sessionPath := setupCollection()

			props := map[string]dbus.Variant{
				InterfaceItem + ".Label":      dbus.MakeVariant("Replace Test"),
				InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "replace", "user": "alice"}),
			}
			itemPath1, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("secret-one")}, false)
			Expect(err).NotTo(HaveOccurred())

			// Store the original UUID to verify it is the same entry after replace.
			originalEntry := findEntryByItemPath(coll, itemPath1)
			originalUUID := fmt.Sprintf("%x", originalEntry.UUID[:])

			props[InterfaceItem+".Label"] = dbus.MakeVariant("Replace Test Updated")
			itemPath2, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("secret-two")}, true)
			Expect(err).NotTo(HaveOccurred())
			Expect(itemPath1).To(Equal(itemPath2), "replace changed item path")

			_, reopened := openWritableTestDB(path, "password")
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
			Expect(count).To(Equal(1))
			Expect(found.GetTitle()).To(Equal("Replace Test Updated"))
			Expect(found.GetPassword()).To(Equal("secret-two"))
		})

		It("preserves the previous version in history", func() {
			path, coll, _, sessionPath := setupCollection()

			props := map[string]dbus.Variant{
				InterfaceItem + ".Label":      dbus.MakeVariant("History Test"),
				InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "history"}),
			}
			itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("first-password")}, false)
			Expect(err).NotTo(HaveOccurred())

			_, _, err = coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("second-password")}, true)
			Expect(err).NotTo(HaveOccurred())

			_, reopened := openWritableTestDB(path, "password")
			entry := findEntryByItemPathOnDB(reopened, itemPath)
			Expect(entry).NotTo(BeNil(), "entry not found after reopen")
			Expect(entry.Histories).NotTo(BeEmpty())
			Expect(entry.Histories[0].Entries).NotTo(BeEmpty())
			Expect(entry.Histories[0].Entries[0].GetPassword()).To(Equal("first-password"))
		})
	})
})

var _ = Describe("SetSecret", func() {
	It("updates the password on disk", func() {
		path, coll, _, sessionPath := setupCollection()

		props := map[string]dbus.Variant{
			InterfaceItem + ".Label":      dbus.MakeVariant("Update Test"),
			InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "test"}),
		}
		itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("old-password")}, false)
		Expect(err).NotTo(HaveOccurred())

		item := newItem(nil, coll, findEntryByItemPath(coll, itemPath))
		Expect(item.SetSecret(DBusSecret{Session: sessionPath, Value: []byte("new-password")})).To(Succeed())

		_, reopened := openWritableTestDB(path, "password")
		entries := reopened.RootEntries()
		var found *gokeepasslib.Entry
		for i := range entries {
			if entries[i].GetTitle() == "Update Test" {
				found = &entries[i]
				break
			}
		}
		Expect(found).NotTo(BeNil(), "updated item not found after reopen")
		Expect(found.GetPassword()).To(Equal("new-password"))
	})

	It("does not return a stale password", func() {
		_, coll, _, sessionPath := setupCollection()

		props := map[string]dbus.Variant{
			InterfaceItem + ".Label":      dbus.MakeVariant("Stale Test"),
			InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "stale"}),
		}
		itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("old-password")}, false)
		Expect(err).NotTo(HaveOccurred())

		item := newItem(nil, coll, findEntryByItemPath(coll, itemPath))
		Expect(item.SetSecret(DBusSecret{Session: sessionPath, Value: []byte("new-password")})).To(Succeed())

		secret, derr := item.GetSecret("", sessionPath)
		Expect(derr).NotTo(HaveOccurred())
		Expect(string(secret.Value)).To(Equal("new-password"))
	})
})

var _ = Describe("Item.Delete", func() {
	It("removes the entry from the database", func() {
		path, coll, _, sessionPath := setupCollection()

		props := map[string]dbus.Variant{
			InterfaceItem + ".Label":      dbus.MakeVariant("Delete Test"),
			InterfaceItem + ".Attributes": dbus.MakeVariant(map[string]string{"application": "delete"}),
		}
		itemPath, _, err := coll.CreateItem(props, DBusSecret{Session: sessionPath, Value: []byte("delete-me")}, false)
		Expect(err).NotTo(HaveOccurred())

		item := newItem(nil, coll, findEntryByItemPath(coll, itemPath))
		_, derr := item.Delete()
		Expect(derr).NotTo(HaveOccurred())

		_, reopened := openWritableTestDB(path, "password")
		entries := reopened.RootEntries()
		for i := range entries {
			Expect(entries[i].GetTitle()).NotTo(Equal("Delete Test"), "deleted item still present after reopen")
		}
	})
})

func findEntryByItemPath(coll *Collection, itemPath dbus.ObjectPath) gokeepasslib.Entry {
	coll.db.RLock()
	defer coll.db.RUnlock()
	uuid := pathUUID(itemPath)
	entry := findEntryPtrByUUID(coll.db.Db.Content.Root.Groups, uuid)
	Expect(entry).NotTo(BeNil(), "entry not found for path %s", itemPath)
	return *entry
}

func findEntryByItemPathOnDB(odb *dbpool.OpenDatabase, itemPath dbus.ObjectPath) *gokeepasslib.Entry {
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
