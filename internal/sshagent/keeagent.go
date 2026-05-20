//go:build linux

package sshagent

import (
	"encoding/xml"
	"fmt"
	"log/slog"

	"github.com/tobischo/gokeepasslib/v3"
)

// KeeAgentSettings represents the KeeAgent settings XML stored as an
// entry attachment. These settings control how SSH keys are handled.
type KeeAgentSettings struct {
	XMLName               xml.Name `xml:"KeeAgent"`
	AllowUseOfSshKey      bool     `xml:"allowUseOfSshKey"`
	AddAtDatabaseOpen     bool     `xml:"addAtDatabaseOpen"`
	RemoveAtDatabaseClose bool     `xml:"removeAtDatabaseClose"`
	Location              Location `xml:"location"`
}

// Location describes where the SSH key data is stored.
type Location struct {
	SelectedType string `xml:"selectedType"` // "attachment" or "file"
	Attachment   string `xml:"attachment"`   // attachment name
	FileName     string `xml:"fileName"`     // file path (for "file" type)
}

// ParseKeeAgentSettings parses KeeAgent.settings XML from entry custom data.
// Returns nil if no KeeAgent settings are found.
func ParseKeeAgentSettings(entry *gokeepasslib.Entry) (*KeeAgentSettings, error) {
	for _, cd := range entry.CustomData {
		if cd.Key == "KeeAgent.settings" {
			var settings KeeAgentSettings
			if err := xml.Unmarshal([]byte(cd.Value), &settings); err != nil {
				return nil, fmt.Errorf("sshagent: failed to parse KeeAgent custom data: %w", err)
			}
			return &settings, nil
		}
	}
	return nil, nil
}

// ExtractKeysFromDatabase extracts all SSH keys from a database.
func ExtractKeysFromDatabase(db *gokeepasslib.Database) ([]*Key, error) {
	var keys []*Key

	if db == nil || db.Content == nil || db.Content.Root == nil {
		return nil, nil
	}

	groupCount := len(db.Content.Root.Groups)
	slog.Debug("sshagent: scanning database for SSH keys", "groups", groupCount)

	for i := range db.Content.Root.Groups {
		extractKeysFromGroup(&db.Content.Root.Groups[i], db, &keys)
	}

	slog.Info("sshagent: SSH key extraction complete", "found", len(keys))
	return keys, nil
}

// extractKeysFromGroup recursively extracts SSH keys from entries in a group.
func extractKeysFromGroup(group *gokeepasslib.Group, db *gokeepasslib.Database, keys *[]*Key) {
	for i := range group.Entries {
		key, err := extractKeyFromEntryWithDB(&group.Entries[i], db)
		if err != nil {
			// Errors are already logged by the extraction function.
			continue
		}
		if key != nil {
			*keys = append(*keys, key)
		}
	}
	for i := range group.Groups {
		extractKeysFromGroup(&group.Groups[i], db, keys)
	}
}

// resolveKeeAgentSettingsFromDB looks up the KeeAgent.settings binary
// attachment in the database, decodes it, and parses the XML to get the
// real attachment name and settings.
func resolveKeeAgentSettingsFromDB(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*KeeAgentSettings, error) {
	for _, ref := range entry.Binaries {
		if ref.Name != "KeeAgent.settings" {
			continue
		}
		binary := db.FindBinary(ref.Value.ID)
		if binary == nil {
			return nil, fmt.Errorf("KeeAgent.settings binary not found in database")
		}
		content, err := binary.GetContentBytes()
		if err != nil {
			return nil, fmt.Errorf("decode KeeAgent.settings: %w", err)
		}
		var settings KeeAgentSettings
		if err := xml.Unmarshal(content, &settings); err != nil {
			return nil, fmt.Errorf("parse KeeAgent.settings XML: %w", err)
		}
		slog.Debug("sshagent: resolved KeeAgent.settings from database",
			"entry", entry.GetTitle(),
			"allow", settings.AllowUseOfSshKey,
			"location_type", settings.Location.SelectedType,
			"attachment", settings.Location.Attachment)
		return &settings, nil
	}
	return nil, nil
}

// extractKeyFromEntryWithDB resolves binary references using the database metadata.
func extractKeyFromEntryWithDB(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*Key, error) {
	// Try the full-resolution path first: parse the real KeeAgent.settings
	// XML from the database. This gives us the actual attachment name.
	settings, err := resolveKeeAgentSettingsFromDB(entry, db)
	if err != nil {
		slog.Debug("sshagent: KeeAgent binary resolution failed",
			"entry", entry.GetTitle(), "error", err)
	}
	if settings == nil {
		// Fallback: KeeAgent settings stored in custom data (no binary attachment).
		settings, err = ParseKeeAgentSettings(entry)
		if err != nil {
			slog.Debug("sshagent: KeeAgent custom data parse failed",
				"entry", entry.GetTitle(), "error", err)
			return nil, nil
		}
		if settings == nil {
			// No KeeAgent metadata on this entry — not an SSH key entry.
			return nil, nil
		}
	}

	if !settings.AllowUseOfSshKey {
		slog.Debug("sshagent: KeeAgent disabled for this entry", "entry", entry.GetTitle())
		return nil, nil
	}

	if settings.Location.SelectedType == "file" {
		slog.Warn("sshagent: file-based SSH key locations not supported",
			"entry", entry.GetTitle(),
			"file", settings.Location.FileName)
		return nil, nil
	}

	attachmentName := settings.Location.Attachment

	// If KeeAgent doesn't specify an attachment name, there's nothing we can do.
	if attachmentName == "" {
		slog.Warn("sshagent: KeeAgent enabled but no attachment name specified",
			"entry", entry.GetTitle())
		return nil, nil
	}

	// Resolve the named attachment.
	for _, ref := range entry.Binaries {
		if ref.Name != attachmentName {
			continue
		}
		binary := db.FindBinary(ref.Value.ID)
		if binary == nil {
			slog.Warn("sshagent: KeeAgent attachment not found in database",
				"entry", entry.GetTitle(), "attachment", attachmentName)
			return nil, nil
		}
		content, err := binary.GetContentBytes()
		if err != nil {
			slog.Warn("sshagent: failed to decode KeeAgent attachment",
				"entry", entry.GetTitle(), "attachment", attachmentName, "error", err)
			return nil, nil
		}
		passphrase := entry.GetPassword()
		key, err := ParsePrivateKey(content, passphrase)
		if err != nil {
			slog.Warn("sshagent: failed to parse KeeAgent attachment as SSH key",
				"entry", entry.GetTitle(), "attachment", attachmentName, "error", err)
			return nil, nil
		}
		uuid, _ := entry.UUID.MarshalText()
		key.SetComment(entry.GetTitle())
		key.SetEntryUUID(string(uuid))
		slog.Info("sshagent: extracted SSH key",
			"entry", entry.GetTitle(),
			"attachment", attachmentName,
			"type", key.Format,
			"fingerprint", key.Fingerprint())
		return key, nil
	}

	slog.Warn("sshagent: KeeAgent attachment reference not found in entry",
		"entry", entry.GetTitle(), "attachment", attachmentName)
	return nil, nil
}
