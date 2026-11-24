//go:build linux

package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/crypto/ssh"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
	"github.com/metalgrid/kpxcd/internal/sshagent"
	"github.com/metalgrid/kpxcd/internal/xdg"
)

// doctorIssue is one finding about an old database.
type doctorIssue struct {
	kind    string // "crypto" | "passkey-fields" | "keeagent-legacy" | "passkey-flags" | "ssh-marker"
	entry   string // entry title, if entry-scoped
	detail  string
	fixable bool
}

// doctorReport is the result of a read-only doctor run.
type doctorReport struct {
	path   string
	kdbx4  bool
	issues []doctorIssue
}

func (r *doctorReport) hasFixable() bool {
	for _, i := range r.issues {
		if i.fixable {
			return true
		}
	}
	return false
}

func (r *doctorReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: KDBX4=%v, %d issue(s)\n", r.path, r.kdbx4, len(r.issues))
	for _, i := range r.issues {
		fix := ""
		if i.fixable {
			fix = " [fixable with --fix]"
		}
		fmt.Fprintf(&b, "  - [%s] %s%s: %s\n", i.kind, i.entry, fix, i.detail)
	}
	return b.String()
}

// legacyPasskeyFields maps legacy kpxcd passkey fields to KeePassXC names.
var legacyPasskeyFields = map[string]string{
	"KPEX_PASSKEY_RPID":     "KPEX_PASSKEY_RELYING_PARTY",
	"KPEX_PASSKEY_RPNAME":   "KPXCD_PASSKEY_RPNAME",
	"KPEX_PASSKEY_USER":     "KPEX_PASSKEY_USERNAME",
	"KPEX_PASSKEY_HANDLE":   "KPEX_PASSKEY_USER_HANDLE",
	"KPEX_PASSKEY_CRED_ID":  "KPEX_PASSKEY_CREDENTIAL_ID",
	"KPEX_PASSKEY_PRIV_KEY": "KPEX_PASSKEY_PRIVATE_KEY_PEM",
}

// doctorCheck opens oldPath read-only and reports issues.
func doctorCheck(oldPath, password string) (*doctorReport, error) {
	f, err := os.Open(oldPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return nil, fmt.Errorf("cannot decode %s (wrong password?): %w", oldPath, err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("cannot unlock protected entries: %w", err)
	}

	r := &doctorReport{path: oldPath, kdbx4: db.Header.IsKdbx4()}
	if !r.kdbx4 {
		r.issues = append(r.issues, doctorIssue{kind: "crypto", detail: "KDBX 3.1 vault; --fix creates a fresh KDBX4 vault with new key material", fixable: true})
	}

	var visit func(groups []gokeepasslib.Group)
	visit = func(groups []gokeepasslib.Group) {
		for gi := range groups {
			for ei := range groups[gi].Entries {
				e := &groups[gi].Entries[ei]
				title := e.GetTitle()
				// legacy passkey field names
				for legacy := range legacyPasskeyFields {
					if e.GetContent(legacy) != "" {
						r.issues = append(r.issues, doctorIssue{kind: "passkey-fields", entry: title, detail: fmt.Sprintf("legacy field %s", legacy), fixable: true})
						break
					}
				}
				// passkey entry missing BE/BS flag fields
				if e.GetContent("KPEX_PASSKEY_RELYING_PARTY") != "" || e.GetContent("KPEX_PASSKEY_RPID") != "" {
					if e.GetContent(fido2.KPEXPasskeyFlagBE) == "" {
						r.issues = append(r.issues, doctorIssue{kind: "passkey-flags", entry: title, detail: "no KPEX_PASSKEY_FLAG_BE/BS; KeePassXC will assume BE=1", fixable: true})
					}
				}
				// legacy <KeeAgent> custom data
				for _, cd := range e.CustomData {
					if strings.EqualFold(cd.Key, sshagent.KeeAgentSettingsAttachment) && strings.Contains(cd.Value, "<KeeAgent>") {
						r.issues = append(r.issues, doctorIssue{kind: "keeagent-legacy", entry: title, detail: "legacy <KeeAgent> custom data; KeePassXC cannot read it", fixable: true})
					}
				}
				// SSH key attachment without any governance marker
				hasKey := false
				hasMarker := e.GetContent(sshagent.MarkerSSHKey) != ""
				hasSettings := false
				for _, b := range e.Binaries {
					if strings.EqualFold(b.Name, sshagent.KeeAgentSettingsAttachment) {
						hasSettings = true
					}
				}
				for _, b := range e.Binaries {
					if strings.EqualFold(b.Name, sshagent.KeeAgentSettingsAttachment) {
						continue
					}
					bin := db.FindBinary(b.Value.ID)
					if bin == nil {
						continue
					}
					content, err := bin.GetContentBytes()
					if err != nil {
						continue
					}
					if _, err := ssh.ParseRawPrivateKey(content); err == nil {
						hasKey = true
					}
				}
				if hasKey && !hasMarker && !hasSettings {
					r.issues = append(r.issues, doctorIssue{kind: "ssh-marker", entry: title, detail: "private-key attachment with no kpxcd marker or KeeAgent settings; will not auto-load", fixable: true})
				}
			}
			visit(groups[gi].Groups)
		}
	}
	visit(db.Content.Root.Groups)
	return r, nil
}

// doctorFix creates a FRESH vault at newPath (new MasterSeed/EncryptionIV/
// inner stream key) with all entries copied and legacy metadata migrated.
// The old file is never modified; newPath must not exist.
func doctorFix(oldPath, oldPassword, newPath, newPassword string) (*doctorReport, error) {
	if _, err := os.Lstat(newPath); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing %s", newPath)
	}

	f, err := os.Open(oldPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	old := gokeepasslib.NewDatabase()
	old.Credentials = gokeepasslib.NewPasswordCredentials(oldPassword)
	if err := gokeepasslib.NewDecoder(f).Decode(old); err != nil {
		return nil, fmt.Errorf("cannot decode %s (wrong password?): %w", oldPath, err)
	}
	if err := old.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("cannot unlock protected entries: %w", err)
	}

	rep, err := doctorCheck(oldPath, oldPassword)
	if err != nil {
		return nil, err
	}

	// Fresh database: brand-new key material.
	fresh := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	fresh.Credentials = gokeepasslib.NewPasswordCredentials(newPassword)
	if old.Content != nil && old.Content.Root != nil {
		fresh.Content = old.Content
	}

	migrateEntry := func(e *gokeepasslib.Entry) {
		// passkey field migration to KeePassXC names
		for legacy, modern := range legacyPasskeyFields {
			if v := e.GetContent(legacy); v != "" {
				setEntryValueLocal(e, modern, v, legacy == "KPEX_PASSKEY_PRIV_KEY")
				if idx := e.GetIndex(legacy); idx >= 0 {
					e.Values = append(e.Values[:idx], e.Values[idx+1:]...)
				}
			}
		}
		// passkey missing BE/BS flags -> "0" (kpxcd-made entries register 0)
		if e.GetContent("KPEX_PASSKEY_RELYING_PARTY") != "" {
			if e.GetContent(fido2.KPEXPasskeyFlagBE) == "" {
				setEntryValueLocal(e, fido2.KPEXPasskeyFlagBE, "0", false)
			}
			if e.GetContent(fido2.KPEXPasskeyFlagBS) == "" {
				setEntryValueLocal(e, fido2.KPEXPasskeyFlagBS, "0", false)
			}
		}
		// legacy <KeeAgent> custom data -> real EntrySettings attachment
		for ci, cd := range e.CustomData {
			if strings.EqualFold(cd.Key, sshagent.KeeAgentSettingsAttachment) && strings.Contains(cd.Value, "<KeeAgent>") {
				var l struct {
					Allow      bool   `xml:"allowUseOfSshKey"`
					Autoload   bool   `xml:"addAtDatabaseOpen"`
					Attachment string `xml:"location>attachment"`
				}
				if err := xmlUnmarshal([]byte(cd.Value), &l); err == nil {
					st := &sshagent.EntrySettings{
						AllowUseOfSshKey:           l.Allow,
						AddAtDatabaseOpen:          l.Autoload,
						RemoveAtDatabaseClose:      true,
						LifetimeConstraintDuration: 600,
						Location:                   sshagent.EntryLocation{SelectedType: "attachment", AttachmentName: l.Attachment},
					}
					xmlBytes, err := sshagent.MarshalEntrySettings(st)
					if err == nil {
						bin := fresh.AddBinary(xmlBytes)
						e.Binaries = append(e.Binaries, bin.CreateReference(sshagent.KeeAgentSettingsAttachment))
					}
				}
				e.CustomData = append(e.CustomData[:ci], e.CustomData[ci+1:]...)
				break
			}
		}
		// SSH key attachment without marker -> write the kpxcd marker
		if e.GetContent(sshagent.MarkerSSHKey) == "" {
			hasSettings := false
			for _, b := range e.Binaries {
				if strings.EqualFold(b.Name, sshagent.KeeAgentSettingsAttachment) {
					hasSettings = true
				}
			}
			if !hasSettings {
				for _, b := range e.Binaries {
					if strings.EqualFold(b.Name, sshagent.KeeAgentSettingsAttachment) {
						continue
					}
					bin := old.FindBinary(b.Value.ID)
					if bin == nil {
						continue
					}
					content, err := bin.GetContentBytes()
					if err != nil {
						continue
					}
					if _, err := ssh.ParseRawPrivateKey(content); err == nil {
						setEntryValueLocal(e, sshagent.MarkerSSHKey, b.Name, false)
						break
					}
				}
			}
		}
	}

	var visit func(groups []gokeepasslib.Group)
	visit = func(groups []gokeepasslib.Group) {
		for gi := range groups {
			for ei := range groups[gi].Entries {
				migrateEntry(&groups[gi].Entries[ei])
			}
			visit(groups[gi].Groups)
		}
	}
	visit(fresh.Content.Root.Groups)

	// Rotate once more before encoding (fresh seed already, but harmless and
	// covers the KDBX4 inner key explicitly).
	if err := dbpool.RefreshCrypto(fresh); err != nil {
		return nil, err
	}
	if err := fresh.LockProtectedEntries(); err != nil {
		return nil, err
	}

	if err := xdg.EnsurePrivateDir(filepath.Dir(newPath)); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(newPath), "."+filepath.Base(newPath)+".doctor-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := gokeepasslib.NewEncoder(tmp).Encode(fresh); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, newPath); err != nil {
		return nil, err
	}

	rep.issues = append(rep.issues, doctorIssue{kind: "crypto", detail: fmt.Sprintf("fresh vault written to %s with new MasterSeed/EncryptionIV/inner stream key", newPath), fixable: false})
	return rep, nil
}

func setEntryValueLocal(entry *gokeepasslib.Entry, key, value string, protected bool) {
	idx := entry.GetIndex(key)
	v := gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
	v.Value.Protected.Bool = protected
	if idx >= 0 {
		entry.Values[idx] = v
		return
	}
	entry.Values = append(entry.Values, v)
}

func xmlUnmarshal(data []byte, v any) error {
	return xml.Unmarshal(data, v)
}
