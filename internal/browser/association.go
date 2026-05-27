package browser

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/tobischo/gokeepasslib/v3"
)

const (
	// browserSettingsKey is the custom data key for the browser association entry.
	browserSettingsKey = "KeePassXC-Browser Settings"

	// browserGroupName is the default group name for browser-related entries.
	browserGroupName = "KeePassXC-Browser Passwords"
)

// browserAssociation represents the stored association data.
type browserAssociation struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// findAssociation searches all entries in all unlocked databases for a
// matching browser association (by idKey).
func findAssociation(pool *dbpool.DatabasePool, idKey string) (string, error) {
	dbs := pool.List()
	for _, db := range dbs {
		if db.Locked {
			continue
		}
		db.RLock()
		entries := db.RootEntries()
		db.RUnlock()

		for i := range entries {
			assoc := getEntryAssociation(&entries[i])
			if assoc != nil && assoc.Key == idKey {
				return db.UUID, nil
			}
		}
	}
	return "", fmt.Errorf("association not found")
}

// storeAssociation creates or updates the browser association entry.
// It writes the association data into the specified database.
func storeAssociation(pool *dbpool.DatabasePool, dbUUID string, id, idKey string) error {
	db, err := pool.Get(dbUUID)
	if err != nil {
		return fmt.Errorf("database not found: %w", err)
	}
	if db.Locked {
		return fmt.Errorf("database is locked")
	}

	assoc := browserAssociation{ID: id, Key: idKey}
	assocJSON, err := json.Marshal(assoc)
	if err != nil {
		return fmt.Errorf("marshal association: %w", err)
	}

	err = db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		if kdb.Content == nil || kdb.Content.Root == nil || len(kdb.Content.Root.Groups) == 0 {
			return fmt.Errorf("database has no root group")
		}

		// Find or create the browser group.
		group := findOrCreateGroup(&kdb.Content.Root.Groups[0], browserGroupName)

		// Find or create the settings entry.
		entry := findEntryByTitle(group, browserSettingsKey)
		if entry == nil {
			newEntry := gokeepasslib.NewEntry()
			newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{
				Key:   "Title",
				Value: gokeepasslib.V{Content: browserSettingsKey},
			})
			group.Entries = append(group.Entries, newEntry)
			entry = &group.Entries[len(group.Entries)-1]
		}

		// Update the custom data.
		cdFound := false
		for i := range entry.CustomData {
			if entry.CustomData[i].Key == browserSettingsKey {
				entry.CustomData[i].Value = string(assocJSON)
				cdFound = true
				break
			}
		}
		if !cdFound {
			entry.CustomData = append(entry.CustomData, gokeepasslib.CustomData{
				Key:   browserSettingsKey,
				Value: string(assocJSON),
			})
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("save association: %w", err)
	}

	slog.Info("browser: stored association", "id", id, "db", db.Name)
	return nil
}

// getEntryAssociation returns the parsed association from an entry, or nil.
func getEntryAssociation(entry *gokeepasslib.Entry) *browserAssociation {
	for _, cd := range entry.CustomData {
		if cd.Key == browserSettingsKey {
			var assoc browserAssociation
			if err := json.Unmarshal([]byte(cd.Value), &assoc); err != nil {
				slog.Debug("browser: invalid association JSON", "error", err)
				return nil
			}
			return &assoc
		}
	}
	return nil
}

// findOrCreateGroup finds a group by name (recursive), creating it if needed.
func findOrCreateGroup(root *gokeepasslib.Group, name string) *gokeepasslib.Group {
	if g := findGroupByName(root, name); g != nil {
		return g
	}
	// Create the group.
	newGroup := gokeepasslib.NewGroup()
	newGroup.Name = name
	root.Groups = append(root.Groups, newGroup)
	return &root.Groups[len(root.Groups)-1]
}

// findGroupByName searches for a group by name (recursive).
func findGroupByName(group *gokeepasslib.Group, name string) *gokeepasslib.Group {
	if group.Name == name {
		return group
	}
	for i := range group.Groups {
		if g := findGroupByName(&group.Groups[i], name); g != nil {
			return g
		}
	}
	return nil
}

// findEntryByTitle finds an entry by title within a group (non-recursive).
func findEntryByTitle(group *gokeepasslib.Group, title string) *gokeepasslib.Entry {
	for i := range group.Entries {
		if group.Entries[i].GetTitle() == title {
			return &group.Entries[i]
		}
	}
	return nil
}

// findBrowserGroup searches all unlocked databases for the browser group
// and returns the database UUID and group.
func findBrowserGroup(pool *dbpool.DatabasePool) (dbUUID string, group *gokeepasslib.Group, err error) {
	dbs := pool.List()
	for _, db := range dbs {
		if db.Locked {
			continue
		}
		db.RLock()
		if db.Db != nil && db.Db.Content != nil && db.Db.Content.Root != nil {
			for i := range db.Db.Content.Root.Groups {
				if g := findGroupByName(&db.Db.Content.Root.Groups[i], browserGroupName); g != nil {
					db.RUnlock()
					return db.UUID, g, nil
				}
			}
		}
		db.RUnlock()
	}
	return "", nil, fmt.Errorf("browser group not found")
}

// generateAssociationID creates a random association identifier.
func generateAssociationID() (string, error) {
	b, err := randomBytes(12)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// matchURL checks if an entry's URL matches the request URL.
// Supports exact match, subdomain matching, and scheme-agnostic matching.
func matchURL(entryURL, requestURL string) bool {
	if entryURL == "" || requestURL == "" {
		return false
	}

	// Exact match after trimming whitespace and trailing slashes.
	eu := strings.TrimRight(strings.TrimSpace(entryURL), "/")
	ru := strings.TrimRight(strings.TrimSpace(requestURL), "/")

	if strings.EqualFold(eu, ru) {
		return true
	}

	// Try subdomain matching: if the entry URL is a domain suffix of the request URL.
	// e.g., entry "https://github.com" matches request "https://gist.github.com"
	if isSubdomainMatch(eu, ru) {
		return true
	}

	return false
}

// isSubdomainMatch checks if requestURL is a subdomain of entryURL.
func isSubdomainMatch(entryURL, requestURL string) bool {
	// Extract hosts.
	eHost := extractHost(entryURL)
	rHost := extractHost(requestURL)
	if eHost == "" || rHost == "" {
		return false
	}

	// Exact host match.
	if strings.EqualFold(eHost, rHost) {
		return true
	}

	// Check if requestHost ends with ".entryHost".
	suffix := "." + eHost
	if strings.HasSuffix(strings.ToLower(rHost), strings.ToLower(suffix)) {
		return true
	}

	return false
}

// extractHost returns the hostname from a URL, or empty string.
func extractHost(urlStr string) string {
	// Simple extraction: strip scheme, path, port.
	u := urlStr
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	if idx := strings.Index(u, ":"); idx >= 0 {
		u = u[:idx]
	}
	return u
}

// findGroupByUUID searches for a group by UUID string (recursive).
func findGroupByUUID(group *gokeepasslib.Group, uuid string) *gokeepasslib.Group {
	if fmt.Sprintf("%x", group.UUID[:]) == uuid {
		return group
	}
	for i := range group.Groups {
		if g := findGroupByUUID(&group.Groups[i], uuid); g != nil {
			return g
		}
	}
	return nil
}

// findEntryByUUID finds an entry by UUID string within a group (non-recursive).
func findEntryByUUID(group *gokeepasslib.Group, uuid string) *gokeepasslib.Entry {
	for i := range group.Entries {
		if fmt.Sprintf("%x", group.Entries[i].UUID[:]) == uuid {
			return &group.Entries[i]
		}
	}
	return nil
}

// findEntryByUsername finds an entry by username and URL within a group.
func findEntryByUsername(group *gokeepasslib.Group, username, url string) *gokeepasslib.Entry {
	for i := range group.Entries {
		if group.Entries[i].GetContent("UserName") == username && group.Entries[i].GetContent("URL") == url {
			return &group.Entries[i]
		}
	}
	return nil
}

// setEntryValue sets a value on an entry, updating in place if the key exists.
func setEntryValue(entry *gokeepasslib.Entry, key, value string) {
	for i := range entry.Values {
		if entry.Values[i].Key == key {
			entry.Values[i].Value.Content = value
			return
		}
	}
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value},
	})
}

// generatePassword generates a random password from the given charset.
func generatePassword(charset string, length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

// serializeGroups converts a group tree to the protocol's JSON format.
func serializeGroups(groups []gokeepasslib.Group) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(groups))
	for _, g := range groups {
		elem := map[string]interface{}{
			"name":    g.Name,
			"uuid":    fmt.Sprintf("%x", g.UUID[:]),
			"children": serializeGroups(g.Groups),
		}
		result = append(result, elem)
	}
	return result
}

// encryptedResponse wraps a response in an encrypted message.
func encryptedResponse(keys *sessionKeys, v any) *Response {
	msg, nonce, err := keys.encryptJSON(v)
	if err != nil {
		return errorResponse("encryption failed")
	}
	return &Response{Message: msg, Nonce: nonce, Success: "true"}
}
