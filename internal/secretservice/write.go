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

func (ss *SecretService) decryptSecret(secret DBusSecret) ([]byte, error) {
	ss.sessionsMu.RLock()
	sess, ok := ss.sessions[secret.Session]
	ss.sessionsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("secretservice: no such session: %s", secret.Session)
	}
	if sess.closed {
		return nil, fmt.Errorf("secretservice: session %s is closed", secret.Session)
	}
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
