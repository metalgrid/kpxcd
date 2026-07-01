//go:build linux

package secretservice

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

const secretServiceGroupName = "Secret Service"

func (ss *SecretService) validateSession(sessionPath dbus.ObjectPath) error {
	ss.sessionsMu.RLock()
	defer ss.sessionsMu.RUnlock()
	sess, ok := ss.sessions[sessionPath]
	if !ok {
		return fmt.Errorf("secretservice: no such session: %s", sessionPath)
	}
	if sess.closed {
		return fmt.Errorf("secretservice: session %s is closed", sessionPath)
	}
	return nil
}

func (ss *SecretService) decryptSecret(secret DBusSecret) ([]byte, error) {
	if err := ss.validateSession(secret.Session); err != nil {
		return nil, err
	}
	ss.sessionsMu.RLock()
	sess := ss.sessions[secret.Session]
	ss.sessionsMu.RUnlock()
	return sess.Decrypt(secret.Parameters, secret.Value)
}

func propertyString(properties map[string]dbus.Variant, property string) string {
	for _, key := range []string{InterfaceItem + "." + property, property} {
		if v, ok := properties[key]; ok {
			if s, ok := v.Value().(string); ok {
				return s
			}
		}
	}
	return ""
}

func propertyAttributes(properties map[string]dbus.Variant) map[string]string {
	for _, key := range []string{InterfaceItem + ".Attributes", "Attributes"} {
		if v, ok := properties[key]; ok {
			switch attrs := v.Value().(type) {
			case map[string]string:
				return cloneAttrs(attrs)
			case map[string]dbus.Variant:
				out := make(map[string]string, len(attrs))
				for k, val := range attrs {
					if s, ok := val.Value().(string); ok {
						out[k] = s
					}
				}
				return out
			}
		}
	}
	return map[string]string{}
}

func cloneAttrs(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	return out
}

func itemPathForEntry(dbName string, entry gokeepasslib.Entry) dbus.ObjectPath {
	return dbus.ObjectPath(CollectionPrefix + sanitizeCollectionName(dbName) + "/" + entryUUIDString(entry))
}

func findEntryPtrByUUID(groups []gokeepasslib.Group, uuidHex string) *gokeepasslib.Entry {
	for gi := range groups {
		for ei := range groups[gi].Entries {
			if entryUUIDString(groups[gi].Entries[ei]) == uuidHex {
				return &groups[gi].Entries[ei]
			}
		}
		if entry := findEntryPtrByUUID(groups[gi].Groups, uuidHex); entry != nil {
			return entry
		}
	}
	return nil
}

// removeEntryByUUID removes the first entry matching uuidHex from groups or
// their subgroups. It returns true if an entry was removed.
func removeEntryByUUID(groups []gokeepasslib.Group, uuidHex string) bool {
	for gi := range groups {
		for ei := range groups[gi].Entries {
			if entryUUIDString(groups[gi].Entries[ei]) == uuidHex {
				groups[gi].Entries = append(groups[gi].Entries[:ei], groups[gi].Entries[ei+1:]...)
				return true
			}
		}
		if removeEntryByUUID(groups[gi].Groups, uuidHex) {
			return true
		}
	}
	return false
}

// updateModificationTime updates the last-modification and last-access times.
func updateModificationTime(entry *gokeepasslib.Entry) {
	now := wrappers.Now()
	entry.Times.LastModificationTime = &now
	entry.Times.LastAccessTime = &now
}

// appendHistory archives the current entry state before mutation. KeePass
// stores historical versions in entry.Histories[0].Entries and trims to the
// database's HistoryMaxItems setting.
func appendHistory(entry *gokeepasslib.Entry, db *gokeepasslib.Database) {
	if entry == nil {
		return
	}
	clone := entry.Clone()
	clone.Histories = nil // history entries don't carry nested history

	if len(entry.Histories) == 0 {
		entry.Histories = append(entry.Histories, gokeepasslib.History{})
	}
	entry.Histories[0].Entries = append(entry.Histories[0].Entries, clone)
	trimHistory(entry, db)
}

func trimHistory(entry *gokeepasslib.Entry, db *gokeepasslib.Database) {
	if len(entry.Histories) == 0 || len(entry.Histories[0].Entries) == 0 {
		return
	}
	maxItems := int64(10)
	maxSize := int64(6 * 1024 * 1024)
	if db != nil && db.Content != nil && db.Content.Meta != nil {
		if db.Content.Meta.HistoryMaxItems > 0 {
			maxItems = db.Content.Meta.HistoryMaxItems
		}
		if db.Content.Meta.HistoryMaxSize > 0 {
			maxSize = db.Content.Meta.HistoryMaxSize
		}
	}

	h := &entry.Histories[0]
	// Drop oldest entries while over the item limit.
	for int64(len(h.Entries)) > maxItems {
		h.Entries = h.Entries[1:]
	}
	// Drop oldest entries while over the size limit (best-effort count).
	for {
		size := historySize(h)
		if size <= maxSize || len(h.Entries) <= 1 {
			break
		}
		h.Entries = h.Entries[1:]
	}
}

func historySize(h *gokeepasslib.History) int64 {
	var size int64
	for _, e := range h.Entries {
		for _, v := range e.Values {
			size += int64(len(v.Key) + len(v.Value.Content))
		}
		size += int64(len(e.Tags) + len(e.OverrideURL))
	}
	return size
}

func findMatchingEntryPtr(groups []gokeepasslib.Group, dbName, dbUUID string, attrs map[string]string) *gokeepasslib.Entry {
	odb := &mockOpenDatabase{Name: dbName, UUID: dbUUID}
	for gi := range groups {
		for ei := range groups[gi].Entries {
			if matchAttributesForWrite(groups[gi].Entries[ei], odb, attrs) {
				return &groups[gi].Entries[ei]
			}
		}
		if entry := findMatchingEntryPtr(groups[gi].Groups, dbName, dbUUID, attrs); entry != nil {
			return entry
		}
	}
	return nil
}

// mockOpenDatabase is the subset of dbpool.OpenDatabase used by match helpers.
type mockOpenDatabase struct {
	Name string
	UUID string
}

func matchAttributesForWrite(entry gokeepasslib.Entry, odb *mockOpenDatabase, attrs map[string]string) bool {
	for key, value := range attrs {
		switch key {
		case AttrDBNamePrefix:
			if !strings.EqualFold(odb.Name, value) {
				return false
			}
		case AttrDBUUIDPrefix:
			if !strings.EqualFold(odb.UUID, value) {
				return false
			}
		default:
			if !entryHasAttribute(entry, key, value) {
				return false
			}
		}
	}
	return true
}

func entryHasAttribute(entry gokeepasslib.Entry, key, value string) bool {
	switch key {
	case AttrTitle:
		return strings.EqualFold(entry.GetTitle(), value)
	case AttrUserName, "username":
		return strings.EqualFold(entry.GetContent("UserName"), value)
	case AttrURL, "url":
		return strings.EqualFold(entry.GetContent("URL"), value)
	case AttrNotes:
		return strings.EqualFold(entry.GetContent("Notes"), value)
	}
	for _, v := range entry.Values {
		if v.Key == key && strings.EqualFold(v.Value.Content, value) {
			return true
		}
	}
	return false
}

func findOrCreateSecretServiceGroup(db *gokeepasslib.Database) *gokeepasslib.Group {
	if db.Content == nil {
		db.Content = gokeepasslib.NewContent()
	}
	if db.Content.Root == nil {
		db.Content.Root = gokeepasslib.NewRootData()
	}
	if len(db.Content.Root.Groups) == 0 {
		root := gokeepasslib.NewGroup()
		root.Name = "Root"
		db.Content.Root.Groups = append(db.Content.Root.Groups, root)
	}
	root := &db.Content.Root.Groups[0]
	for i := range root.Groups {
		if root.Groups[i].Name == secretServiceGroupName {
			return &root.Groups[i]
		}
	}
	group := gokeepasslib.NewGroup()
	group.Name = secretServiceGroupName
	root.Groups = append(root.Groups, group)
	return &root.Groups[len(root.Groups)-1]
}

func newSecretServiceEntry(label string, attrs map[string]string, secret []byte) gokeepasslib.Entry {
	entry := gokeepasslib.NewEntry()
	applyEntryFields(&entry, label, attrs, string(secret))
	return entry
}

func applyEntryFields(entry *gokeepasslib.Entry, label string, attrs map[string]string, secret string) {
	if label == "" {
		label = attrs[AttrTitle]
	}
	if label == "" {
		label = attrs["application"]
	}
	if label == "" {
		label = "Secret Service Item"
	}

	setEntryValue(entry, "Title", label, false)
	setEntryValue(entry, "Password", secret, true)

	for key, value := range attrs {
		switch key {
		case AttrDBNamePrefix, AttrDBUUIDPrefix:
			continue
		case AttrTitle:
			// Label owns KeePass Title; keep Secret Service title searches working.
			setEntryValue(entry, "Title", label, false)
		case AttrUserName, "username":
			setEntryValue(entry, "UserName", value, false)
		case AttrURL, "url":
			setEntryValue(entry, "URL", value, false)
		case AttrNotes:
			setEntryValue(entry, "Notes", value, false)
		default:
			setEntryValue(entry, key, value, false)
		}
	}

	now := wrappers.Now()
	entry.Times.LastModificationTime = &now
	entry.Times.LastAccessTime = &now
}

func applyEntryAttributes(entry *gokeepasslib.Entry, attrs map[string]string) {
	for key, value := range attrs {
		switch key {
		case AttrDBNamePrefix, AttrDBUUIDPrefix:
			continue
		case AttrTitle:
			setEntryValue(entry, "Title", value, false)
		case AttrUserName, "username":
			setEntryValue(entry, "UserName", value, false)
		case AttrURL, "url":
			setEntryValue(entry, "URL", value, false)
		case AttrNotes:
			setEntryValue(entry, "Notes", value, false)
		default:
			setEntryValue(entry, key, value, false)
		}
	}
	now := wrappers.Now()
	entry.Times.LastModificationTime = &now
}

func setEntryValue(entry *gokeepasslib.Entry, key, value string, protected bool) {
	idx := entry.GetIndex(key)
	v := gokeepasslib.ValueData{
		Key: key,
		Value: gokeepasslib.V{
			Content:   value,
			Protected: wrappers.BoolWrapper{Bool: protected},
		},
	}
	if idx >= 0 {
		entry.Values[idx] = v
		return
	}
	entry.Values = append(entry.Values, v)
}

func exportItemIfPossible(coll *Collection, item *Item) {
	if coll.conn == nil {
		return
	}
	path := item.Path()
	if err := coll.conn.Export(item, path, InterfaceItem); err != nil {
		slog.Warn("secretservice: export created item", "path", path, "error", err)
	}
	coll.conn.Export(introspect.NewIntrospectable(itemIntrospectNode(item)), path, "org.freedesktop.DBus.Introspectable")
	coll.conn.Export(newItemProperties(item), path, "org.freedesktop.DBus.Properties")
}
