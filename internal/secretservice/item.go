//go:build linux

package secretservice

import (
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/user/kpxcd/internal/dbpool"
	"github.com/user/kpxcd/internal/security"
)

const (
	// ServicePath is the root path of the Secret Service.
	ServicePath = "/org/freedesktop/secrets"
	// CollectionPrefix is the prefix for collection paths.
	CollectionPrefix = ServicePath + "/collection/"
	// ItemPrefix is the prefix for item paths within a collection.
	ItemPrefix = ServicePath + "/collection/"

	// InterfaceCollection is the DBus interface for collections.
	InterfaceCollection = "org.freedesktop.Secret.Collection"
	// InterfaceItem is the DBus interface for items.
	InterfaceItem = "org.freedesktop.Secret.Item"
	// InterfaceService is the DBus interface for the service.
	InterfaceService = "org.freedesktop.Secret.Service"
	// InterfaceSession is the DBus interface for sessions.
	InterfaceSession = "org.freedesktop.Secret.Session"
	// InterfacePrompt is the DBus interface for prompts.
	InterfacePrompt = "org.freedesktop.Secret.Prompt"

	// ErrorPrefix is the prefix for Secret Service error names.
	ErrorPrefix = "org.freedesktop.Secret.Error."
)

// Item represents a single KeePass entry exposed via the Secret Service.
type Item struct {
	conn     *dbus.Conn
	path     dbus.ObjectPath
	coll     *Collection
	entry    gokeepasslib.Entry
	db       *dbpool.OpenDatabase
}

// newItem creates a new Item wrapping a KeePass entry.
func newItem(conn *dbus.Conn, coll *Collection, entry gokeepasslib.Entry) *Item {
	entryUUID := entryUUIDString(entry)
	itemPath := dbus.ObjectPath(CollectionPrefix + sanitizeCollectionName(coll.db.Name) + "/" + entryUUID)

	return &Item{
		conn:  conn,
		path:  itemPath,
		coll:  coll,
		entry: entry,
		db:    coll.db,
	}
}

// Path returns the DBus object path of this item.
func (i *Item) Path() dbus.ObjectPath {
	return i.path
}

// Locked returns whether this item is locked. Items in an unlocked collection
// are never locked themselves.
func (i *Item) Locked() bool {
	return false
}

// Label returns the entry's title.
func (i *Item) Label() string {
	return i.entry.GetTitle()
}

// Attributes returns the Secret Service attributes for this entry.
func (i *Item) Attributes() map[string]string {
	i.db.RLock()
	defer i.db.RUnlock()
	return EntryAttributes(i.db, i.entry)
}

// Created returns the Unix timestamp of when this entry was created.
func (i *Item) Created() int64 {
	if i.entry.Times.CreationTime != nil {
		return i.entry.Times.CreationTime.Time.Unix()
	}
	return 0
}

// Modified returns the Unix timestamp of when this entry was last modified.
func (i *Item) Modified() int64 {
	if i.entry.Times.LastModificationTime != nil {
		return i.entry.Times.LastModificationTime.Time.Unix()
	}
	return 0
}

// Delete removes this item. Since this is a read-only view of the KeePass
// database, deletion is not supported.
func (i *Item) Delete() (dbus.ObjectPath, *dbus.Error) {
	return "/", dbus.NewError(ErrorPrefix+"NotSupported",
		[]interface{}{"Items cannot be deleted through the Secret Service API"})
}

// Secret returns the encrypted secret for this entry via the given session.
func (i *Item) Secret(sessionPath dbus.ObjectPath) (map[string]interface{}, *dbus.Error) {
	svc := i.coll.svc
	svc.sessionsMu.RLock()
	sess, ok := svc.sessions[sessionPath]
	svc.sessionsMu.RUnlock()
	if !ok {
		return nil, dbus.NewError(ErrorPrefix+"NoSuchSession",
			[]interface{}{"No such session"})
	}

	if sess.closed {
		return nil, dbus.NewError(ErrorPrefix+"NoSuchSession",
			[]interface{}{"Session is closed"})
	}

	// Get the password from the entry and encrypt inside security.Do()
	// to ensure plaintext is zeroed from registers and stack after use.
	var iv []byte
	var ciphertext []byte
	var secretErr error

	security.Do(func() {
		i.db.RLock()
		password := i.entry.GetPassword()
		i.db.RUnlock()

		// Encrypt the password using the session.
		iv, ciphertext, secretErr = sess.Encrypt([]byte(password))
	})
	if secretErr != nil {
		return nil, dbus.NewError(ErrorPrefix+"InternalError",
			[]interface{}{secretErr.Error()})
	}

	// Build the Secret struct as a map[string]interface{} for DBus variant encoding.
	// Secret = { session: o, parameters: ay, value: ay, content_type: s }
	secret := map[string]interface{}{
		"session":      sessionPath,
		"parameters":   iv,
		"value":        ciphertext,
		"content_type": "text/plain",
	}

	return secret, nil
}

// entryUUIDString returns a safe string representation of an entry's UUID
// for use in DBus object paths. Uses hex encoding (only [0-9a-f]) which
// is always valid in DBus paths. Base64 from MarshalText() contains '='
// and '+' which are invalid.
func entryUUIDString(entry gokeepasslib.Entry) string {
	return fmt.Sprintf("%x", entry.UUID[:])
}

// sanitizeCollectionName makes a database name safe for use in DBus object paths.
// DBus paths only allow [A-Za-z0-9_] as element characters.
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
	// Ensure it doesn't start with a digit (not valid as first char).
	if len(result) > 0 && result[0] >= '0' && result[0] <= '9' {
		result = append([]byte{'_'}, result...)
	}
	if len(result) == 0 {
		return "_"
	}
	return string(result)
}
