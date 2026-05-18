//go:build linux

package secretservice

import (
	"log/slog"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/user/kpxcd/internal/dbpool"
)

// Collection represents a single unlocked KeePass database exposed via
// the Secret Service as a collection of items.
type Collection struct {
	conn *dbus.Conn
	path dbus.ObjectPath
	db   *dbpool.OpenDatabase
	svc  *SecretService
}

// newCollection creates a new Collection for the given database.
func newCollection(conn *dbus.Conn, svc *SecretService, db *dbpool.OpenDatabase) *Collection {
	name := sanitizeCollectionName(db.Name)
	collPath := dbus.ObjectPath(CollectionPrefix + name)

	return &Collection{
		conn: conn,
		path: collPath,
		db:   db,
		svc:  svc,
	}
}

// Path returns the DBus object path of this collection.
func (c *Collection) Path() dbus.ObjectPath {
	return c.path
}

// Locked returns whether this collection is locked.
func (c *Collection) Locked() bool {
	c.db.RLock()
	defer c.db.RUnlock()
	return c.db.Locked
}

// Label returns the display name of this collection (the database name).
func (c *Collection) Label() string {
	return c.db.Name
}

// Created returns the Unix timestamp of when this collection was created.
// For a KeePass database, this is the root group's creation time.
func (c *Collection) Created() int64 {
	c.db.RLock()
	defer c.db.RUnlock()
	if c.db.Db != nil && c.db.Db.Content != nil && c.db.Db.Content.Root != nil {
		if len(c.db.Db.Content.Root.Groups) > 0 &&
			c.db.Db.Content.Root.Groups[0].Times.CreationTime != nil {
			return c.db.Db.Content.Root.Groups[0].Times.CreationTime.Time.Unix()
		}
	}
	return 0
}

// Modified returns the Unix timestamp of when this collection was last modified.
func (c *Collection) Modified() int64 {
	c.db.RLock()
	defer c.db.RUnlock()
	if c.db.Db != nil && c.db.Db.Content != nil && c.db.Db.Content.Root != nil {
		if len(c.db.Db.Content.Root.Groups) > 0 &&
			c.db.Db.Content.Root.Groups[0].Times.LastModificationTime != nil {
			return c.db.Db.Content.Root.Groups[0].Times.LastModificationTime.Time.Unix()
		}
	}
	return 0
}

// Items returns the list of item paths in this collection.
func (c *Collection) Items() ([]dbus.ObjectPath, *dbus.Error) {
	c.db.RLock()
	defer c.db.RUnlock()

	if c.db.Locked || c.db.Db == nil || c.db.Db.Content == nil {
		return nil, nil
	}

	items := c.svc.itemsForCollection(c.path)
	paths := make([]dbus.ObjectPath, 0, len(items))
	for _, item := range items {
		paths = append(paths, item.Path())
	}
	return paths, nil
}

// SearchItems searches for items in this collection matching the given attributes.
func (c *Collection) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	strAttrs := attributes

	c.db.RLock()
	defer c.db.RUnlock()

	if c.db.Locked || c.db.Db == nil || c.db.Db.Content == nil {
		return nil, nil
	}

	var results []dbus.ObjectPath
	allEntries := collectEntries(c.db.Db.Content.Root.Groups)
	for _, entry := range allEntries {
		if MatchAttributes(entry, c.db, strAttrs) {
			itemPath := CollectionPrefix + sanitizeCollectionName(c.db.Name) + "/" + entryUUIDString(entry)
			results = append(results, dbus.ObjectPath(itemPath))
		}
	}
	return results, nil
}

// Delete removes this collection. Since this is a read-only view of the
// database, deletion is not supported.
func (c *Collection) Delete() (dbus.ObjectPath, *dbus.Error) {
	return "/", dbus.NewError(ErrIsLocked,
		[]interface{}{"Collections cannot be deleted through the Secret Service API"})
}

// CreateItem creates a new item in this collection.
// Since kpxcd is a read-only view of KeePass databases, this returns
// an immediate prompt that completes with dismissal (not supported).
func (c *Collection) CreateItem(properties map[string]dbus.Variant, secret DBusSecret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: CreateItem", "collection", string(c.path), "replace", replace)

	// Read-only: return a prompt path. When the client calls Prompt(),
	// it auto-completes with dismissed=true (operation cancelled).
	_, promptPath := c.svc.nextPrompt()
	return "/", promptPath, nil
}

// CreatePrompt creates a prompt for the collection. Used internally.
func (c *Collection) createPrompt() *Prompt {
	promptPath := dbus.ObjectPath(ServicePath + "/prompt/" +
		time.Now().Format("20060102150405.000000000"))
	return NewPrompt(c.conn, promptPath)
}

// items returns all items in this collection. Must be called with db lock held.
func (c *Collection) items() []*Item {
	if c.db.Locked || c.db.Db == nil || c.db.Db.Content == nil {
		return nil
	}

	entries := collectEntries(c.db.Db.Content.Root.Groups)
	items := make([]*Item, 0, len(entries))
	for _, entry := range entries {
		item := newItem(c.conn, c, entry)
		items = append(items, item)
	}
	return items
}
