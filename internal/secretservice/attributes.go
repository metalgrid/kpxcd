//go:build linux

package secretservice

import (
	"strings"

	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/dbpool"
)

// Well-known Secret Service attribute keys.
const (
	AttrTitle    = "title"
	AttrUserName = "UserName"
	AttrURL      = "URL"
	AttrNotes    = "Notes"

	// kpxcd-specific attribute prefixes.
	AttrDBNamePrefix = "kpxcd:dbname"
	AttrDBUUIDPrefix = "kpxcd:dbuuid"
	AttrCustomPrefix = "custom:"
)

// EntryAttributes maps a KeePass entry to Secret Service attributes.
func EntryAttributes(odb *dbpool.OpenDatabase, entry gokeepasslib.Entry) map[string]string {
	attrs := make(map[string]string)

	// kpxcd metadata.
	attrs[AttrDBNamePrefix] = odb.Name
	attrs[AttrDBUUIDPrefix] = odb.UUID

	// Standard fields.
	attrs[AttrTitle] = entry.GetTitle()
	attrs[AttrUserName] = entry.GetContent("UserName")
	attrs[AttrURL] = entry.GetContent("URL")

	// Notes: first line only (per spec convention).
	notes := entry.GetContent("Notes")
	if idx := strings.Index(notes, "\n"); idx >= 0 {
		notes = notes[:idx]
	}
	if notes != "" {
		attrs[AttrNotes] = notes
	}

	// Custom attributes — returned with raw key names (no prefix), matching KeePassXC.
	// This is critical: libsecret/VSCode searches for attributes like "application"
	// directly, not "custom:application".
	standardKeys := map[string]bool{
		"Title":    true,
		"UserName": true,
		"URL":      true,
		"Notes":    true,
		"Password": true,
	}
	for _, v := range entry.Values {
		if standardKeys[v.Key] {
			continue
		}
		if strings.HasPrefix(v.Key, "KPH:") {
			continue
		}
		attrs[v.Key] = v.Value.Content
	}

	return attrs
}

// MatchAttributes checks if an entry matches the given search attributes.
// All provided attributes must match (AND logic).
func MatchAttributes(entry gokeepasslib.Entry, odb *dbpool.OpenDatabase, attributes map[string]string) bool {
	for key, value := range attributes {
		if !matchAttribute(entry, odb, key, value) {
			return false
		}
	}
	return true
}

// matchAttribute checks a single attribute against an entry.
func matchAttribute(entry gokeepasslib.Entry, odb *dbpool.OpenDatabase, key, value string) bool {
	switch key {
	case AttrTitle:
		return strings.EqualFold(entry.GetTitle(), value) ||
			strings.Contains(strings.ToLower(entry.GetTitle()), strings.ToLower(value))
	case AttrUserName:
		return strings.EqualFold(entry.GetContent("UserName"), value)
	case AttrURL:
		return strings.EqualFold(entry.GetContent("URL"), value) ||
			strings.Contains(strings.ToLower(entry.GetContent("URL")), strings.ToLower(value))
	case AttrNotes:
		return strings.Contains(strings.ToLower(entry.GetContent("Notes")), strings.ToLower(value))
	case AttrDBNamePrefix:
		return strings.EqualFold(odb.Name, value)
	case AttrDBUUIDPrefix:
		return strings.EqualFold(odb.UUID, value)
	default:
		// Check custom attributes.
		if strings.HasPrefix(key, AttrCustomPrefix) {
			customKey := strings.TrimPrefix(key, AttrCustomPrefix)
			for _, v := range entry.Values {
				if v.Key == customKey && strings.EqualFold(v.Value.Content, value) {
					return true
				}
			}
			return false
		}
		// Unknown attribute: check all custom fields.
		for _, v := range entry.Values {
			if v.Key == key && strings.EqualFold(v.Value.Content, value) {
				return true
			}
		}
		return false
	}
}

// SearchResult holds a matching entry with its database context.
type SearchResult struct {
	Database *dbpool.OpenDatabase
	Entry    gokeepasslib.Entry
}

// SearchEntries searches all unlocked databases for entries matching the
// given attributes. Returns a list of (database, entry) pairs.
func SearchEntries(pool *dbpool.DatabasePool, attributes map[string]string) []SearchResult {
	if len(attributes) == 0 {
		return nil
	}

	var results []SearchResult

	dbs := pool.List()
	for _, odb := range dbs {
		odb.RLock()
		if odb.Locked || odb.Db == nil || odb.Db.Content == nil {
			odb.RUnlock()
			continue
		}

		recycleBinUUID := dbpool.RecycleBinUUIDForDB(odb.Db)
		for _, entry := range collectEntries(odb.Db.Content.Root.Groups, recycleBinUUID) {
			if MatchAttributes(entry, odb, attributes) {
				results = append(results, SearchResult{
					Database: odb,
					Entry:    entry,
				})
			}
		}
		odb.RUnlock()
	}

	return results
}

// collectEntries recursively collects all entries from a list of groups,
// excluding the recycle bin.
func collectEntries(groups []gokeepasslib.Group, recycleBinUUID gokeepasslib.UUID) []gokeepasslib.Entry {
	var entries []gokeepasslib.Entry
	for i := range groups {
		g := &groups[i]
		if dbpool.IsRecycled(g, recycleBinUUID) {
			continue
		}
		entries = append(entries, g.Entries...)
		entries = append(entries, collectEntries(g.Groups, recycleBinUUID)...)
	}
	return entries
}
