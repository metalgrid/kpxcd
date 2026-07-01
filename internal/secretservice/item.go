//go:build linux

package secretservice

import (
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
	itemPath := dbus.ObjectPath(CollectionPrefix + sanitizeCollectionName(coll.db.Name) + "/" + entryUUID)
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

// refresh updates the cached entry by looking it up in the database by UUID.
// Returns a pointer to the cached entry, or nil if the entry no longer exists.
func (i *Item) refresh() *gokeepasslib.Entry {
	i.db.RLock()
	defer i.db.RUnlock()
	if i.db.Db == nil || i.db.Db.Content == nil || i.db.Db.Content.Root == nil {
		return nil
	}
	if entry := findEntryPtrByUUID(i.db.Db.Content.Root.Groups, i.entryUUID); entry != nil {
		i.entry = *entry
		return &i.entry
	}
	return nil
}

// Locked returns whether this item is locked.
func (i *Item) Locked() bool { return false }

// Label returns the entry's title.
func (i *Item) Label() string {
	i.refresh()
	return i.entry.GetTitle()
}

// Attributes returns the Secret Service attributes for this entry.
func (i *Item) Attributes() map[string]string {
	i.refresh()
	i.db.RLock()
	defer i.db.RUnlock()
	return EntryAttributes(i.db, i.entry)
}

// Created returns the Unix timestamp of when this entry was created.
func (i *Item) Created() int64 {
	i.refresh()
	if i.entry.Times.CreationTime != nil {
		return i.entry.Times.CreationTime.Time.Unix()
	}
	return 0
}

// Modified returns the Unix timestamp of when this entry was last modified.
func (i *Item) Modified() int64 {
	i.refresh()
	if i.entry.Times.LastModificationTime != nil {
		return i.entry.Times.LastModificationTime.Time.Unix()
	}
	return 0
}

// Delete removes this item and persists the database.
func (i *Item) Delete() (dbus.ObjectPath, *dbus.Error) {
	if i.refresh() == nil {
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
	if i.refresh() == nil {
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
	i.refresh()
	slog.Info("secretservice: item secret updated", "path", string(i.path), "collection", i.coll.db.Name)
	return nil
}

// GetSecret returns the encrypted secret for this entry via the given session.
// Method name matches spec: org.freedesktop.Secret.Item.GetSecret.
// Returns a Secret struct (oayays).
func (i *Item) GetSecret(sender dbus.Sender, sessionPath dbus.ObjectPath) (DBusSecret, *dbus.Error) {
	if i.refresh() == nil {
		return DBusSecret{}, dbus.NewError(ErrNoSuchObject,
			[]interface{}{"item no longer exists"})
	}

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

	svc.sessionsMu.RLock()
	sess, ok := svc.sessions[sessionPath]
	svc.sessionsMu.RUnlock()
	if !ok {
		return DBusSecret{}, dbus.NewError(ErrNoSession,
			[]interface{}{"No such session"})
	}
	if sess.closed {
		return DBusSecret{}, dbus.NewError(ErrNoSession,
			[]interface{}{"Session is closed"})
	}

	var iv []byte
	var ciphertext []byte
	var secretErr error

	security.Do(func() {
		password := i.entry.GetPassword()
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
