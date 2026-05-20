//go:build linux

package sshagent

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"strings"

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

// ParseKeeAgentSettings parses KeeAgent.settings XML from an entry's attachments.
// Returns nil if no KeeAgent settings are found.
func ParseKeeAgentSettings(entry *gokeepasslib.Entry) (*KeeAgentSettings, error) {
	// Look for KeeAgent.settings attachment reference.
	for _, ref := range entry.Binaries {
		if ref.Name == "KeeAgent.settings" {
			slog.Debug("sshagent: found KeeAgent.settings attachment reference",
				"entry", entry.GetTitle())
			return &KeeAgentSettings{
				AllowUseOfSshKey:      true,
				AddAtDatabaseOpen:     true,
				RemoveAtDatabaseClose: true,
				Location: Location{
					SelectedType: "attachment",
					Attachment:   "",
				},
			}, nil
		}
	}

	// Also check entry custom data for KeeAgent settings (some formats store it there).
	for _, cd := range entry.CustomData {
		if cd.Key == "KeeAgent.settings" {
			slog.Debug("sshagent: found KeeAgent.settings in custom data", "entry", entry.GetTitle())
			var settings KeeAgentSettings
			if err := xml.Unmarshal([]byte(cd.Value), &settings); err != nil {
				return nil, fmt.Errorf("sshagent: failed to parse KeeAgent custom data: %w", err)
			}
			return &settings, nil
		}
	}

	// No KeeAgent settings found.
	return nil, nil
}

// ExtractKeyFromEntry extracts an SSH key from a KeePass entry.
// Requires the database to resolve binary attachments.
func ExtractKeyFromEntry(entry *gokeepasslib.Entry, settings *KeeAgentSettings) (*Key, error) {
	if settings == nil || !settings.AllowUseOfSshKey {
		return nil, nil
	}

	// Determine where to find the key data.
	switch settings.Location.SelectedType {
	case "attachment":
		return extractKeyFromAttachmentRef(entry, settings.Location.Attachment)
	case "file":
		// File-based keys are not supported in the daemon.
		return nil, fmt.Errorf("sshagent: file-based SSH key locations not supported")
	default:
		// Try to find a key by common attachment names.
		return extractKeyFromCommonNames(entry)
	}
}

// extractKeyFromAttachmentRef extracts an SSH key from a named attachment reference.
func extractKeyFromAttachmentRef(entry *gokeepasslib.Entry, name string) (*Key, error) {
	// Look for binary data in entry attachments.
	// The attachment name might be "KeeAgent.settings", in which case we need
	// to find the actual key data alongside it.
	for _, ref := range entry.Binaries {
		if ref.Name == name {
			// We need the actual content. In gokeepasslib, the content
			// is stored in db.Content.Meta.Binaries referenced by ID.
			// For now, try extracting the key from entry values (password field)
			// or other attachments.
			return extractKeyFromCommonNames(entry)
		}
	}

	// No specific attachment found, try common names.
	return extractKeyFromCommonNames(entry)
}

// extractKeyFromCommonNames tries to find an SSH key by common attachment names
// or from entry password/attribute data.
func extractKeyFromCommonNames(entry *gokeepasslib.Entry) (*Key, error) {
	// Try to find key data in entry values (private key stored as attribute).
	// KeePassXC sometimes stores SSH keys as custom attributes.
	for _, v := range entry.Values {
		if v.Key == "PrivateKey" || v.Key == "SSH Private Key" {
			if v.Value.Content != "" {
				passphrase := entry.GetPassword()
				return ParsePrivateKey([]byte(v.Value.Content), passphrase)
			}
		}
	}

	// Try to find key data in entry binary references.
	privateKeyNames := []string{
		"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
		"private.key", "ssh.key", "key.pem",
	}

	for _, ref := range entry.Binaries {
		name := strings.ToLower(ref.Name)
		for _, pattern := range privateKeyNames {
			if name == pattern || strings.HasSuffix(name, ".pem") {
				// We need the binary content, but it's stored in the database
				// metadata by reference ID. Without access to the database,
				// we can't resolve it here.
				// This will be handled by ExtractKeysFromDatabase.
				_ = ref
				continue
			}
		}
	}

	return nil, fmt.Errorf("sshagent: no SSH key found in entry")
}

// ExtractKeysFromDatabase extracts all SSH keys from a database that have
// KeeAgent settings configured.
func ExtractKeysFromDatabase(db *gokeepasslib.Database) ([]*Key, error) {
	var keys []*Key

	if db == nil || db.Content == nil || db.Content.Root == nil {
		slog.Debug("sshagent: database has no content to extract keys from")
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
			// Errors are already logged by the extraction functions.
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
		slog.Debug("sshagent: KeeAgent DB resolution failed, trying fallback",
			"entry", entry.GetTitle(), "error", err)
	}
	if settings == nil {
		// No KeeAgent.settings binary attachment. Try custom data or
		// fall back to common name scanning.
		settings, err = ParseKeeAgentSettings(entry)
		if err != nil {
			slog.Debug("sshagent: KeeAgent parse error, trying fallback",
				"entry", entry.GetTitle(), "error", err)
			return extractKeyFromCommonNamesWithDB(entry, db)
		}
		if settings == nil {
			slog.Debug("sshagent: no KeeAgent settings, trying fallback", "entry", entry.GetTitle())
			return extractKeyFromCommonNamesWithDB(entry, db)
		}
	}

	if !settings.AllowUseOfSshKey {
		slog.Debug("sshagent: KeeAgent explicitly disabled for this entry", "entry", entry.GetTitle())
		return nil, nil
	}

	slog.Info("sshagent: KeeAgent enabled for entry",
		"entry", entry.GetTitle(),
		"location_type", settings.Location.SelectedType,
		"attachment", settings.Location.Attachment)

	// Find the attachment data.
	var keyData []byte
	attachmentName := settings.Location.Attachment

	// If the attachment name is empty or points to the settings file itself,
	// we don't know the real key attachment — fall through to common names.
	if attachmentName != "" && attachmentName != "KeeAgent.settings" {
		// Resolve the specific attachment named in KeeAgent settings.
		for _, ref := range entry.Binaries {
			if ref.Name == attachmentName {
				binary := db.FindBinary(ref.Value.ID)
				if binary != nil {
					content, err := binary.GetContentBytes()
					if err == nil && len(content) > 0 {
						keyData = content
						slog.Debug("sshagent: resolved named KeeAgent attachment",
							"entry", entry.GetTitle(), "attachment", attachmentName)
						break
					}
				}
			}
		}
	}

	// If we didn't find the named attachment (or didn't know the name),
	// search for any binary that looks like a private key.
	if keyData == nil {
		slog.Debug("sshagent: named attachment not resolved, scanning common names",
			"entry", entry.GetTitle())
		return extractKeyFromCommonNamesWithDB(entry, db)
	}

	passphrase := entry.GetPassword()
	key, err := ParsePrivateKey(keyData, passphrase)
	if err != nil {
		slog.Warn("sshagent: failed to parse KeeAgent named attachment",
			"entry", entry.GetTitle(), "attachment", attachmentName, "error", err)
		return nil, err
	}
	return key, nil
}

// extractKeyFromCommonNamesWithDB resolves binary attachments using the database.
func extractKeyFromCommonNamesWithDB(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*Key, error) {
	if db == nil || db.Content == nil {
		return nil, nil
	}

	binaries := entry.Binaries
	slog.Info("sshagent: scanning binaries for key-like names",
		"entry", entry.GetTitle(), "binary_count", len(binaries))

	for _, ref := range binaries {
		match := isPrivateKeyFilename(ref.Name)
		slog.Info("sshagent: checking binary",
			"entry", entry.GetTitle(),
			"name", ref.Name,
			"matches_key_pattern", match)
		if !match {
			continue
		}
		binary := db.FindBinary(ref.Value.ID)
		if binary == nil {
			slog.Warn("sshagent: binary not found in database",
				"entry", entry.GetTitle(), "name", ref.Name, "id", ref.Value.ID)
			continue
		}
		content, err := binary.GetContentBytes()
		if err != nil || len(content) == 0 {
			slog.Warn("sshagent: failed to decode binary content",
				"entry", entry.GetTitle(), "name", ref.Name, "error", err)
			continue
		}
		passphrase := entry.GetPassword()
		key, err := ParsePrivateKey(content, passphrase)
		if err != nil {
			slog.Warn("sshagent: binary looks like a key but failed to parse",
				"entry", entry.GetTitle(),
				"name", ref.Name,
				"size", len(content),
				"error", err)
			continue
		}
		if key != nil {
			uuid, _ := entry.UUID.MarshalText()
			key.SetComment(entry.GetTitle())
			key.SetEntryUUID(string(uuid))
			slog.Info("sshagent: extracted SSH key from entry",
				"entry", entry.GetTitle(),
				"binary", ref.Name,
				"type", key.Format,
				"fingerprint", key.Fingerprint())
			return key, nil
		}
	}

	slog.Info("sshagent: no SSH key found in entry binaries",
		"entry", entry.GetTitle(),
		"binary_count", len(binaries))
	return nil, nil
}

// isPrivateKeyFilename returns true if the name looks like an SSH private key file.
func isPrivateKeyFilename(name string) bool {
	lower := strings.ToLower(name)

	// Known SSH private key filenames.
	privateKeyNames := []string{
		"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
		"id_rsa_old", // legacy KeeAgent naming
		"private.key", "ssh.key",
	}
	for _, pattern := range privateKeyNames {
		if lower == pattern {
			return true
		}
	}

	// Generic extensions.
	if strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") {
		return true
	}

	// OpenSSH new-format private key (often used by KeeAgent when the
	// attachment name is derived from the key comment or a custom name).
	// These are base names that commonly hold key material.
	sshKeyPrefixes := []string{"id_", "ssh_", "key", "private"}
	for _, prefix := range sshKeyPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	return false
}