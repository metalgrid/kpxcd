//go:build linux

package secretservice

import (
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/security"
)

const (
	ServicePath      = "/org/freedesktop/secrets"
	CollectionPrefix = ServicePath + "/collection/"

	InterfaceService    = "org.freedesktop.Secret.Service"
	InterfaceCollection = "org.freedesktop.Secret.Collection"
	InterfaceItem       = "org.freedesktop.Secret.Item"
	InterfaceSession    = "org.freedesktop.Secret.Session"
	InterfacePrompt     = "org.freedesktop.Secret.Prompt"

	// Error names per spec §15.
	ErrIsLocked     = "org.freedesktop.Secret.Error.IsLocked"
	ErrNoSession    = "org.freedesktop.Secret.Error.NoSession"
	ErrNoSuchObject = "org.freedesktop.Secret.Error.NoSuchObject"
	ErrAccessDenied = "org.freedesktop.DBus.Error.AccessDenied"
)

// DBusSecret is the Secret struct per the spec: (oayays).
// godbus encodes this as a DBus struct with the correct wire format.
type DBusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// Item represents a single KeePass entry exposed via the Secret Service.
type Item struct {
	conn      *dbus.Conn
	path      dbus.ObjectPath
	coll      *Collection
	entry     gokeepasslib.Entry
	entryUUID string
	db        *dbpool.OpenDatabase
}

func newItem(conn *dbus.Conn, coll *Collection, entry gokeepasslib.Entry) *Item {
	entryUUID := entryUUIDString(entry)
	itemPath := itemPathForDB(coll.db, entry)
	return &Item{
		conn:      conn,
		path:      itemPath,
		coll:      coll,
		entry:     entry,
		entryUUID: entryUUID,
		db:        coll.db,
	}
}

func (i *Item) Path() dbus.ObjectPath { return i.path }

// withEntry runs fn with the current entry copy under a single database read
// lock. It reports whether the entry exists and the database is unlocked.
// Exported Item objects are shared across D-Bus handler goroutines, so the
// cached entry must never be written from a reader; fn receives a value copy
// and all field reads happen under the lock (Values shares backing with the
// live database). fn must not take database locks again.
func (i *Item) withEntry(fn func(gokeepasslib.Entry)) bool {
	i.db.RLock()
	defer i.db.RUnlock()
	if i.db.Locked || i.db.Db == nil || i.db.Db.Content == nil || i.db.Db.Content.Root == nil {
		return false
	}
	for _, entry := range i.coll.svc.collectEntriesForDB(i.db) {
		if entryUUIDString(entry) == i.entryUUID {
			fn(entry)
			return true
		}
	}
	return false
}

// currentPassword returns the entry's password, read under one database read
// lock. It fails closed when the database is locked or the entry is gone —
// after a lock or an external removal, a stale item must not serve an empty
// or wiped value as if it were the password.
func (i *Item) currentPassword() (string, *dbus.Error) {
	var password string
	ok := i.withEntry(func(e gokeepasslib.Entry) { password = e.GetPassword() })
	if !ok {
		return "", dbus.NewError(ErrNoSuchObject,
			[]interface{}{"item no longer exists or database is locked"})
	}
	return password, nil
}

// Locked returns whether this item is locked.
func (i *Item) Locked() bool { return false }

// Label returns the entry's title.
func (i *Item) Label() string {
	var label string
	i.withEntry(func(e gokeepasslib.Entry) { label = e.GetTitle() })
	return label
}

// Attributes returns the Secret Service attributes for this entry.
func (i *Item) Attributes() map[string]string {
	attrs := map[string]string{}
	i.db.RLock()
	defer i.db.RUnlock()
	if i.db.Locked || i.db.Db == nil || i.db.Db.Content == nil || i.db.Db.Content.Root == nil {
		return attrs
	}
	for _, entry := range i.coll.svc.collectEntriesForDB(i.db) {
		if entryUUIDString(entry) == i.entryUUID {
			return EntryAttributes(i.db, entry)
		}
	}
	return attrs
}

// Created returns the Unix timestamp of when this entry was created.
func (i *Item) Created() int64 {
	var ts int64
	i.withEntry(func(e gokeepasslib.Entry) {
		if e.Times.CreationTime != nil {
			ts = e.Times.CreationTime.Time.Unix()
		}
	})
	return ts
}

// Modified returns the Unix timestamp of when this entry was last modified.
func (i *Item) Modified() int64 {
	var ts int64
	i.withEntry(func(e gokeepasslib.Entry) {
		if e.Times.LastModificationTime != nil {
			ts = e.Times.LastModificationTime.Time.Unix()
		}
	})
	return ts
}

// Delete removes this item and persists the database.
func (i *Item) Delete() (dbus.ObjectPath, *dbus.Error) {
	if !i.withEntry(func(gokeepasslib.Entry) {}) {
		return "/", dbus.NewError(ErrNoSuchObject,
			[]interface{}{"item no longer exists"})
	}
	uuid := i.entryUUID
	if err := i.db.UpdateAndSave(func(db *gokeepasslib.Database) error {
		if !removeEntryByUUID(db.Content.Root.Groups, uuid) {
			return fmt.Errorf("secretservice: item not found: %s", uuid)
		}
		return nil
	}); err != nil {
		return "/", dbus.NewError(ErrIsLocked, []interface{}{err.Error()})
	}

	if i.conn != nil {
		_ = i.conn.Export(nil, i.path, InterfaceItem)
		_ = i.conn.Emit(i.coll.path, InterfaceCollection+".ItemDeleted", i.path)
	}
	slog.Info("secretservice: item deleted", "path", string(i.path), "collection", i.coll.db.Name)
	return "/", nil
}

// SetSecret updates this item's secret and persists the database.
func (i *Item) SetSecret(secret DBusSecret) *dbus.Error {
	if err := i.coll.svc.validateSession(secret.Session); err != nil {
		return dbus.NewError(ErrNoSession, []interface{}{err.Error()})
	}
	plaintext, err := i.coll.svc.decryptSecret(secret)
	if err != nil {
		return dbus.NewError(ErrNoSession, []interface{}{err.Error()})
	}
	if !i.withEntry(func(gokeepasslib.Entry) {}) {
		return dbus.NewError(ErrNoSuchObject, []interface{}{"item no longer exists"})
	}
	uuid := i.entryUUID
	if err := i.db.UpdateAndSave(func(db *gokeepasslib.Database) error {
		entry := findEntryPtrByUUID(db.Content.Root.Groups, uuid)
		if entry == nil {
			return fmt.Errorf("secretservice: item not found: %s", uuid)
		}
		appendHistory(entry, db)
		setEntryValue(entry, "Password", string(plaintext), true)
		updateModificationTime(entry)
		return nil
	}); err != nil {
		return dbus.NewError(ErrIsLocked, []interface{}{err.Error()})
	}
	slog.Info("secretservice: item secret updated", "path", string(i.path), "collection", i.coll.db.Name)
	return nil
}

// GetSecret returns the encrypted secret for this entry via the given session.
// Method name matches spec: org.freedesktop.Secret.Item.GetSecret.
// Returns a Secret struct (oayays).
func (i *Item) GetSecret(sender dbus.Sender, sessionPath dbus.ObjectPath) (DBusSecret, *dbus.Error) {
	svc := i.coll.svc
	caller := svc.callerInfo(sender)
	if err := svc.authorizeSecretAccess(caller, i); err != nil {
		slog.Warn("secretservice: item secret access denied",
			"sender", caller.Sender,
			"pid", caller.PID,
			"app", caller.AppName(),
			"collection", i.coll.db.Name,
			"item", i.Label(),
			"error", err)
		return DBusSecret{}, dbus.NewError(ErrAccessDenied,
			[]interface{}{err.Error()})
	}

	sess := svc.getSession(sessionPath)
	if sess == nil {
		return DBusSecret{}, dbus.NewError(ErrNoSession,
			[]interface{}{"No such session"})
	}
	if sess.isClosed() {
		return DBusSecret{}, dbus.NewError(ErrNoSession,
			[]interface{}{"Session is closed"})
	}

	// Read the password under one lock AFTER authorization: a lock or reload
	// during the wait must fail the request, not serve a stale value.
	password, perr := i.currentPassword()
	if perr != nil {
		return DBusSecret{}, perr
	}

	var iv []byte
	var ciphertext []byte
	var secretErr error

	security.Do(func() {
		iv, ciphertext, secretErr = sess.Encrypt([]byte(password))
	})
	if secretErr != nil {
		return DBusSecret{}, dbus.NewError(ErrIsLocked,
			[]interface{}{secretErr.Error()})
	}

	slog.Debug("secretservice: GetSecret", "item", string(i.path), "session", string(sessionPath), "sender", string(sender))
	svc.logSecretAccess(caller, i, "Item.GetSecret")
	svc.notifySecretAccess(caller, i)
	return DBusSecret{
		Session:     sessionPath,
		Parameters:  iv,
		Value:       ciphertext,
		ContentType: "text/plain",
	}, nil
}

// entryUUIDString returns a hex-encoded UUID safe for DBus paths.
func entryUUIDString(entry gokeepasslib.Entry) string {
	return fmt.Sprintf("%x", entry.UUID[:])
}

// collectionPathFor builds the collection object path from the database
// name plus a UUID suffix, so two databases with the same file basename do
// not collide on one path. The suffix is hex (the pool's UUID text form is
// base64 with '+', '/', '='), and the separator is '_' because D-Bus object
// path elements allow only [A-Za-z0-9_].
func collectionPathFor(name, uuid string) dbus.ObjectPath {
	suffix := hex.EncodeToString([]byte(uuid))
	if len(suffix) > 16 {
		suffix = suffix[:16]
	}
	return dbus.ObjectPath(CollectionPrefix + sanitizeCollectionName(name) + "_" + suffix)
}

// itemPathForDB builds the item object path inside the database's collection.
func itemPathForDB(db *dbpool.OpenDatabase, entry gokeepasslib.Entry) dbus.ObjectPath {
	return collectionPathFor(db.Name, db.UUID) + dbus.ObjectPath("/"+entryUUIDString(entry))
}

// sanitizeCollectionName makes a name safe for DBus object path elements.
func sanitizeCollectionName(name string) string {
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	if len(result) > 0 && result[0] >= '0' && result[0] <= '9' {
		result = append([]byte{'_'}, result...)
	}
	if len(result) == 0 {
		return "_"
	}
	return string(result)
}

// itemTypeIntrospection returns the introspection node for an item,
// including the GetSecret method with correct out signature.
func itemIntrospectNode(item *Item) *introspect.Node {
	return &introspect.Node{
		Name: string(item.path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name: InterfaceItem,
				Methods: []introspect.Method{
					{Name: "Delete", Args: []introspect.Arg{
						{Name: "prompt", Type: "o", Direction: "out"},
					}},
					{Name: "GetSecret", Args: []introspect.Arg{
						{Name: "session", Type: "o", Direction: "in"},
						{Name: "secret", Type: "(oayays)", Direction: "out"},
					}},
					{Name: "SetSecret", Args: []introspect.Arg{
						{Name: "secret", Type: "(oayays)", Direction: "in"},
					}},
				},
				Properties: itemIntrospectProperties(),
			},
			propertiesIntrospectData(),
		},
	}
}

// collectEntriesSafe safely collects entries from a database.
func collectEntriesSafe(db *dbpool.OpenDatabase) []gokeepasslib.Entry {
	if db.Db == nil || db.Db.Content == nil || db.Db.Content.Root == nil {
		return nil
	}
	return collectEntries(db.Db.Content.Root.Groups, dbpool.RecycleBinUUIDForDB(db.Db))
}
