//go:build linux

package sshagent

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/dbpool"
)

// MarkerSSHKey is the kpxcd-owned entry field naming the attachment that
// holds the entry's SSH private key. Presence means usable and auto-load.
// Written by generate/import/autoload; any KeePass editor can set it as a
// custom attribute, so KeePassXC is never required.
const MarkerSSHKey = "KPXCD_SSH_KEY"

// KeeAgentSettingsAttachment is the attachment name KeePassXC uses for its
// per-entry SSH agent settings.
const KeeAgentSettingsAttachment = "KeeAgent.settings"

// EntrySettings mirrors KeePassXC's KeeAgentSettings XML (root
// <EntrySettings>, PascalCase fields), as written by KeePassXC's toXml().
type EntrySettings struct {
	XMLName                         xml.Name      `xml:"EntrySettings"`
	AllowUseOfSshKey                bool          `xml:"AllowUseOfSshKey"`
	AddAtDatabaseOpen               bool          `xml:"AddAtDatabaseOpen"`
	RemoveAtDatabaseClose           bool          `xml:"RemoveAtDatabaseClose"`
	UseConfirmConstraintWhenAdding  bool          `xml:"UseConfirmConstraintWhenAdding"`
	UseLifetimeConstraintWhenAdding bool          `xml:"UseLifetimeConstraintWhenAdding"`
	LifetimeConstraintDuration      int           `xml:"LifetimeConstraintDuration"`
	Location                        EntryLocation `xml:"Location"`
}

// EntryLocation is the <Location> element of EntrySettings.
type EntryLocation struct {
	SelectedType             string `xml:"SelectedType"` // "attachment" or "file"
	AttachmentName           string `xml:"AttachmentName"`
	SaveAttachmentToTempFile bool   `xml:"SaveAttachmentToTempFile"`
	FileName                 string `xml:"FileName"`
}

// legacyKeeAgentSettings is the old kpxcd <KeeAgent> custom-data form.
// Read-only: never written anymore.
type legacyKeeAgentSettings struct {
	XMLName               xml.Name          `xml:"KeeAgent"`
	AllowUseOfSshKey      bool              `xml:"allowUseOfSshKey"`
	AddAtDatabaseOpen     bool              `xml:"addAtDatabaseOpen"`
	RemoveAtDatabaseClose bool              `xml:"removeAtDatabaseClose"`
	Location              legacyKeeLocation `xml:"location"`
}

type legacyKeeLocation struct {
	SelectedType string `xml:"selectedType"`
	Attachment   string `xml:"attachment"`
	FileName     string `xml:"fileName"`
}

// stripBOM removes a UTF-16 BOM and, if present, transcodes UTF-16 to UTF-8.
// The KeePass2 KeeAgent plugin is believed to write UTF-16 settings.
func stripBOM(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		return utf16BEToUTF8(b[2:])
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return utf16LEToUTF8(b[2:])
	}
	return b
}

func utf16BEToUTF8(b []byte) []byte {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return []byte(string(utf16.Decode(u16)))
}

func utf16LEToUTF8(b []byte) []byte {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return []byte(string(utf16.Decode(u16)))
}

// ParseEntrySettings parses KeePassXC-format EntrySettings XML, including
// UTF-16 (with BOM, or without one via a null-byte heuristic — encoding/xml
// cannot detect BOM-less UTF-16 itself).
func ParseEntrySettings(data []byte) (*EntrySettings, error) {
	data = stripBOM(data)
	if len(data) >= 4 && data[0] != 0 && data[1] == 0 {
		data = utf16LEToUTF8(data) // BOM-less UTF-16LE
	} else if len(data) >= 4 && data[0] == 0 && data[1] != 0 {
		data = utf16BEToUTF8(data) // BOM-less UTF-16BE
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	// The input was already transcoded to UTF-8 above (BOM or null-byte
	// heuristic), so the charset label is irrelevant: pass through.
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var s EntrySettings
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("sshagent: parse EntrySettings: %w", err)
	}
	return &s, nil
}

// MarshalEntrySettings encodes settings in KeePassXC's writer shape.
func MarshalEntrySettings(s *EntrySettings) ([]byte, error) {
	body, err := xml.Marshal(s)
	if err != nil {
		return nil, err
	}
	// Inject the xmlns attributes into the root element, matching
	// KeePassXC's toXml() output.
	root := "<EntrySettings>"
	withNS := `<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`
	if !strings.HasPrefix(string(body), root) {
		return nil, fmt.Errorf("sshagent: unexpected encoder output root")
	}
	header := `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	return []byte(header + strings.Replace(string(body), root, withNS, 1)), nil
}

// parseLegacyKeeAgentSettings reads the old kpxcd <KeeAgent> custom-data
// form. Read-only compatibility.
func parseLegacyKeeAgentSettings(entry *gokeepasslib.Entry) *legacyKeeAgentSettings {
	for _, cd := range entry.CustomData {
		if strings.EqualFold(cd.Key, KeeAgentSettingsAttachment) {
			var s legacyKeeAgentSettings
			if err := xml.Unmarshal(stripBOM([]byte(cd.Value)), &s); err != nil {
				slog.Warn("sshagent: unreadable legacy KeeAgent custom data", "entry", entry.GetTitle(), "error", err)
				return nil
			}
			return &s
		}
	}
	return nil
}

// resolveEntrySettings reads the KeeAgent.settings attachment from the
// database. Returns (nil, nil) when absent; (nil, err) when present but
// unreadable — callers must Warn and treat as absent, never as allowed.
func resolveEntrySettings(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*EntrySettings, error) {
	for _, ref := range entry.Binaries {
		if !strings.EqualFold(ref.Name, KeeAgentSettingsAttachment) {
			continue
		}
		content, err := attachmentContent(db, ref.Name, ref.Value.ID)
		if err != nil {
			return nil, err
		}
		return ParseEntrySettings(content)
	}
	return nil, nil
}

// keyRef describes how an entry's SSH key is governed.
type keyRef struct {
	attachment string // attachment holding the private key
	source     string // "keeagent" | "marker" | "legacy"
	autoLoad   bool
	denied     bool
	confirm    bool
	lifetime   uint32
}

// resolveKeyRef applies the read order: a valid KeeAgent deny wins; valid
// KeeAgent allow is authoritative for auto-load; otherwise our own marker;
// otherwise legacy custom data; otherwise nothing. KeePassXC is never
// required — the marker alone is sufficient. Settings that exist but are
// unreadable fail CLOSED for auto-load (we cannot rule out a deny): ref has
// source "keeagent-unreadable" and autoLoad=false; explicit add may still
// proceed via the marker.
func resolveKeyRef(entry *gokeepasslib.Entry, db *gokeepasslib.Database) keyRef {
	settings, err := resolveEntrySettings(entry, db)
	if err != nil {
		slog.Warn("sshagent: KeeAgent.settings unreadable; not auto-loading", "entry", entry.GetTitle(), "error", err)
		return keyRef{source: "keeagent-unreadable"}
	}
	if settings != nil {
		if !settings.AllowUseOfSshKey {
			return keyRef{denied: true, source: "keeagent"}
		}
		ref := keyRef{
			attachment: settings.Location.AttachmentName,
			source:     "keeagent",
			autoLoad:   settings.AddAtDatabaseOpen,
			confirm:    settings.UseConfirmConstraintWhenAdding,
		}
		if settings.UseLifetimeConstraintWhenAdding {
			ref.lifetime = uint32(settings.LifetimeConstraintDuration)
		}
		if settings.Location.SelectedType == "file" {
			slog.Warn("sshagent: file-based SSH key locations not supported", "entry", entry.GetTitle(), "file", settings.Location.FileName)
			ref.attachment = ""
		}
		return ref
	}
	if marker := entry.GetContent(MarkerSSHKey); marker != "" {
		return keyRef{attachment: marker, source: "marker", autoLoad: true}
	}
	if legacy := parseLegacyKeeAgentSettings(entry); legacy != nil {
		if !legacy.AllowUseOfSshKey {
			return keyRef{denied: true, source: "legacy"}
		}
		return keyRef{
			attachment: legacy.Location.Attachment,
			source:     "legacy",
			autoLoad:   legacy.AddAtDatabaseOpen,
		}
	}
	return keyRef{}
}

// ExtractKeysFromDatabase extracts every parseable, non-denied SSH key in
// the database (any group except the recycle bin), regardless of auto-load.
// Used by ssh scan and by reload reconcile.
func ExtractKeysFromDatabase(db *gokeepasslib.Database) ([]*Key, error) {
	return extractKeys(db, false)
}

// ExtractAutoLoadKeysFromDatabase extracts only keys marked auto-load.
// Used when a database is unlocked.
func ExtractAutoLoadKeysFromDatabase(db *gokeepasslib.Database) ([]*Key, error) {
	return extractKeys(db, true)
}

func extractKeys(db *gokeepasslib.Database, autoLoadOnly bool) ([]*Key, error) {
	var keys []*Key

	if db == nil || db.Content == nil || db.Content.Root == nil {
		return nil, nil
	}

	recycleBinUUID := dbpool.RecycleBinUUIDForDB(db)
	for i := range db.Content.Root.Groups {
		extractKeysFromGroup(&db.Content.Root.Groups[i], db, recycleBinUUID, autoLoadOnly, &keys)
	}

	slog.Info("sshagent: SSH key extraction complete", "found", len(keys))
	return keys, nil
}

func extractKeysFromGroup(group *gokeepasslib.Group, db *gokeepasslib.Database, recycleBinUUID gokeepasslib.UUID, autoLoadOnly bool, keys *[]*Key) {
	if dbpool.IsRecycled(group, recycleBinUUID) {
		return
	}
	for i := range group.Entries {
		key, err := extractKeyFromEntryWithDB(&group.Entries[i], db, autoLoadOnly)
		if err != nil {
			slog.Warn("sshagent: skipping entry with unusable key", "entry", group.Entries[i].GetTitle(), "error", err)
			continue
		}
		if key != nil {
			*keys = append(*keys, key)
		}
	}
	for i := range group.Groups {
		extractKeysFromGroup(&group.Groups[i], db, recycleBinUUID, autoLoadOnly, keys)
	}
}

// ExtractKeyFromEntry extracts one entry's SSH key for an explicit
// `ssh add`: the governed attachment when metadata exists, otherwise the
// single parseable private-key attachment of a bare entry.
func ExtractKeyFromEntry(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*Key, error) {
	ref := resolveKeyRef(entry, db)
	if ref.denied {
		return nil, fmt.Errorf("sshagent: entry is denied by KeeAgent settings")
	}
	name, err := ChooseKeyAttachment(entry, db)
	if err != nil {
		return nil, err
	}
	key, err := parseKeyAttachment(entry, db, name)
	if err != nil {
		return nil, err
	}
	key.Confirm = ref.confirm
	key.Lifetime = ref.lifetime
	logExtractedKey(entry, name, key)
	return key, nil
}

func extractKeyFromEntryWithDB(entry *gokeepasslib.Entry, db *gokeepasslib.Database, autoLoadOnly bool) (*Key, error) {
	ref := resolveKeyRef(entry, db)
	if ref.denied || ref.attachment == "" {
		return nil, nil
	}
	if autoLoadOnly && !ref.autoLoad {
		return nil, nil
	}
	key, err := parseKeyAttachment(entry, db, ref.attachment)
	if err != nil {
		return nil, err
	}
	key.Confirm = ref.confirm
	key.Lifetime = ref.lifetime
	logExtractedKey(entry, ref.attachment, key)
	return key, nil
}

func attachmentNameMatches(got, want string) bool {
	if got == want || strings.EqualFold(got, want) {
		return true
	}
	return strings.EqualFold(filepath.Base(got), filepath.Base(want))
}

func parseKeyAttachment(entry *gokeepasslib.Entry, db *gokeepasslib.Database, attachmentName string) (*Key, error) {
	var id int
	var found bool
	for _, ref := range entry.Binaries {
		if attachmentNameMatches(ref.Name, attachmentName) {
			id = ref.Value.ID
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("attachment %q not found in entry", attachmentName)
	}
	content, err := attachmentContent(db, attachmentName, id)
	if err != nil {
		return nil, err
	}
	return parseKeyBytes(entry, content)
}

func attachmentContent(db *gokeepasslib.Database, attachmentName string, id int) ([]byte, error) {
	binary := db.FindBinary(id)
	if binary == nil {
		return nil, fmt.Errorf("attachment %q binary not found in database", attachmentName)
	}
	content, err := binary.GetContentBytes()
	if err != nil {
		return nil, fmt.Errorf("decode attachment %q: %w", attachmentName, err)
	}
	return content, nil
}

func parseKeyBytes(entry *gokeepasslib.Entry, content []byte) (*Key, error) {
	passphrase := entry.GetPassword()
	key, err := ParsePrivateKey(content, passphrase)
	if err != nil && passphrase != "" {
		// Some databases use the KeePass entry password for account login and keep
		// an unencrypted SSH private key attachment. Try without passphrase too.
		key, err = ParsePrivateKey(content, "")
	}
	if err != nil {
		return nil, err
	}
	if key.Signer == nil {
		return nil, fmt.Errorf("sshagent: encrypted key without passphrase cannot be loaded; set the entry password to the key passphrase")
	}
	uuid, _ := entry.UUID.MarshalText()
	key.SetComment(entry.GetTitle())
	key.SetEntryUUID(string(uuid))
	return key, nil
}

func logExtractedKey(entry *gokeepasslib.Entry, attachmentName string, key *Key) {
	slog.Info("sshagent: extracted SSH key",
		"entry", entry.GetTitle(),
		"attachment", attachmentName,
		"type", key.Format,
		"fingerprint", key.Fingerprint())
}

// ChooseKeyAttachment picks the attachment holding an entry's private key:
// the valid KeeAgent settings' attachment name, else the KPXCD_SSH_KEY
// marker, else the legacy form, else the single parseable candidate. When
// several bare candidates exist the error lists them.
func ChooseKeyAttachment(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (string, error) {
	ref := resolveKeyRef(entry, db)
	if ref.source == "keeagent" || ref.source == "legacy" {
		if ref.attachment != "" {
			return ref.attachment, nil
		}
	}
	if ref.source == "marker" && ref.attachment != "" {
		return ref.attachment, nil
	}
	// Bare entry: exactly one parseable private-key attachment.
	var candidates []string
	for _, b := range entry.Binaries {
		if strings.EqualFold(b.Name, KeeAgentSettingsAttachment) {
			continue
		}
		content, err := attachmentContent(db, b.Name, b.Value.ID)
		if err != nil {
			continue
		}
		if _, err := parseKeyBytes(entry, content); err == nil {
			candidates = append(candidates, b.Name)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("sshagent: no parseable private-key attachment in entry %q", entry.GetTitle())
	}
	return "", fmt.Errorf("sshagent: %d parseable key attachments %v; mark one with %s", len(candidates), candidates, MarkerSSHKey)
}

// ScannedKey is one parseable key found by ScanKeys, with its governance.
type ScannedKey struct {
	Key        *Key
	EntryUUID  string
	Title      string
	Attachment string
	Source     string
	AutoLoad   bool
	Denied     bool
}

// ScanKeys lists every parseable private-key attachment in the database
// (any group except the recycle bin), governed or not — used by ssh scan,
// reload reconcile, and export. Agent loading uses the stricter extractors.
func ScanKeys(db *gokeepasslib.Database) []ScannedKey {
	var out []ScannedKey
	if db == nil || db.Content == nil || db.Content.Root == nil {
		return nil
	}
	recycleBinUUID := dbpool.RecycleBinUUIDForDB(db)
	var visit func(groups []gokeepasslib.Group)
	visit = func(groups []gokeepasslib.Group) {
		for i := range groups {
			g := &groups[i]
			if dbpool.IsRecycled(g, recycleBinUUID) {
				continue
			}
			for j := range g.Entries {
				entry := &g.Entries[j]
				ref := resolveKeyRef(entry, db)
				attachments := []string{ref.attachment}
				if ref.attachment == "" || ref.source == "keeagent-unreadable" {
					attachments = nil
					for _, b := range entry.Binaries {
						if strings.EqualFold(b.Name, KeeAgentSettingsAttachment) {
							continue
						}
						attachments = append(attachments, b.Name)
					}
				}
				for _, name := range attachments {
					if name == "" {
						continue
					}
					key, err := parseKeyAttachment(entry, db, name)
					if err != nil || key == nil {
						continue
					}
					out = append(out, ScannedKey{
						Key:        key,
						EntryUUID:  fmt.Sprintf("%x", entry.UUID[:]),
						Title:      entry.GetTitle(),
						Attachment: name,
						Source:     ref.source,
						AutoLoad:   ref.autoLoad && !ref.denied,
						Denied:     ref.denied,
					})
					break // one key per entry for scan purposes
				}
			}
			visit(g.Groups)
		}
	}
	visit(db.Content.Root.Groups)
	return out
}

// VerifyKeyAttachment parses the named attachment as a usable private key,
// ignoring governance (deny/allow). Used to validate a choice before writing
// metadata, and for export.
func VerifyKeyAttachment(entry *gokeepasslib.Entry, db *gokeepasslib.Database, name string) error {
	_, err := parseKeyAttachment(entry, db, name)
	return err
}

// ExtractKeyForExport parses the entry's chosen key attachment without any
// governance check: a KeeAgent deny governs agent use, not export (export is
// separately polkit-gated).
func ExtractKeyForExport(entry *gokeepasslib.Entry, db *gokeepasslib.Database) (*Key, error) {
	name, err := ChooseKeyAttachment(entry, db)
	if err != nil {
		return nil, err
	}
	return parseKeyAttachment(entry, db, name)
}
