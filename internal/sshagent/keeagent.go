//go:build linux

package sshagent

import (
	"encoding/xml"
	"fmt"
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
			// We need the actual binary content from the database metadata.
			// This will be resolved by ExtractKeyFromEntry using the database.
			// For now, return a placeholder that indicates attachment-based key.
			// We found a KeeAgent.settings attachment reference but can't
			// resolve its content here (we need the database). Signal that
			// this entry uses attachment-based keys but leave the attachment
			// name empty so the caller falls through to common name search.
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
		return nil, nil
	}

	for i := range db.Content.Root.Groups {
		extractKeysFromGroup(&db.Content.Root.Groups[i], db, &keys)
	}

	return keys, nil
}

// extractKeysFromGroup recursively extracts SSH keys from entries in a group.
func extractKeysFromGroup(group *gokeepasslib.Group, db *gokeepasslib.Database, keys *[]*Key) {
	for i := range group.Entries {
		key, err := extractKeyFromEntryWithDB(&group.Entries[i], db)
		if err != nil {
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

// extractKeyFromEntryWithDB resolves binary references using the database metadata.
func extractKeyFromEntryWithDB(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*Key, error) {
	settings, err := ParseKeeAgentSettings(entry)
	if err != nil || settings == nil || !settings.AllowUseOfSshKey {
		// Even without KeeAgent settings, try common key patterns.
		return extractKeyFromCommonNamesWithDB(entry, db)
	}

	// Find the attachment data.
	var keyData []byte
	attachmentName := settings.Location.Attachment

	// If the attachment name is empty or points to the settings file itself,
	// we don't know the real key attachment — fall through to common names.
	if attachmentName != "" && attachmentName != "KeeAgent.settings" {
		// Resolve the specific attachment named in KeeAgent settings.
		for _, ref := range entry.Binaries {
			if ref.Name == attachmentName {
				binary := db.Content.Meta.Binaries.Find(ref.Value.ID)
				if binary != nil && binary.Content != nil {
					keyData = binary.Content
					break
				}
			}
		}
	}

	// If we didn't find the named attachment (or didn't know the name),
	// search for any binary that looks like a private key.
	if keyData == nil {
		return extractKeyFromCommonNamesWithDB(entry, db)
	}

	passphrase := entry.GetPassword()
	return ParsePrivateKey(keyData, passphrase)
}

// extractKeyFromCommonNamesWithDB resolves binary attachments using the database.
func extractKeyFromCommonNamesWithDB(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*Key, error) {
	if db == nil || db.Content == nil || db.Content.Meta == nil {
		return nil, nil
	}

	for _, ref := range entry.Binaries {
		if !isPrivateKeyFilename(ref.Name) {
			continue
		}
		binary := db.Content.Meta.Binaries.Find(ref.Value.ID)
		if binary != nil && binary.Content != nil {
			passphrase := entry.GetPassword()
			key, err := ParsePrivateKey(binary.Content, passphrase)
			if err == nil && key != nil {
				uuid, _ := entry.UUID.MarshalText()
				key.SetComment(entry.GetTitle())
				key.SetEntryUUID(string(uuid))
				return key, nil
			}
		}
	}

	return nil, nil
}

// isPrivateKeyFilename returns true if the name looks like an SSH private key file.
func isPrivateKeyFilename(name string) bool {
	lower := strings.ToLower(name)
	privateKeyNames := []string{
		"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
		"private.key", "ssh.key",
	}
	for _, pattern := range privateKeyNames {
		if lower == pattern {
			return true
		}
	}
	return strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key")
}