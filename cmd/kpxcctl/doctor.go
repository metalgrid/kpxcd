//go:build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/crypto/ssh"

	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
	"github.com/metalgrid/kpxcd/internal/sshagent"
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
		r.issues = append(r.issues, doctorIssue{kind: "crypto", detail: "KDBX 3.1 vault (kept as-is by --fix; KDBX4 upgrade is a KeePassXC choice)", fixable: false})
	}
	// KDF strength advisory: weak Argon2 memory makes a typed master password
	// cheap to brute-force from any file copy.
	if kdf := db.Header.FileHeaders.KdfParameters; kdf != nil && string(kdf.UUID) == string(gokeepasslib.KdfArgon2) {
		if kdf.Memory < 64*1024*1024 {
			r.issues = append(r.issues, doctorIssue{kind: "crypto", detail: fmt.Sprintf("Argon2 memory is low (%d MiB); raise it in KeePassXC (KDBX settings)", kdf.Memory/(1024*1024)), fixable: false})
		}
	}

	var visit func(groups []gokeepasslib.Group)
	visit = func(groups []gokeepasslib.Group) {
		for gi := range groups {
			for ei := range groups[gi].Entries {
				e := &groups[gi].Entries[ei]
				title := e.GetTitle()
				// legacy passkey field names (read-only report; the daemon migrates on use)
				for _, legacy := range []string{"KPEX_PASSKEY_RPID", "KPEX_PASSKEY_CRED_ID", "KPEX_PASSKEY_HANDLE", "KPEX_PASSKEY_PRIV_KEY"} {
					if e.GetContent(legacy) != "" {
						r.issues = append(r.issues, doctorIssue{kind: "passkey-fields", entry: title, detail: fmt.Sprintf("legacy field %s (read compatibly by the daemon)", legacy), fixable: false})
						break
					}
				}
				// passkey entry missing BE/BS flag fields
				// Only kpxcd-made entries (they carry KPEX_PASSKEY_PUB_KEY)
				// get flags backfilled on sign; foreign entries' absent flags
				// are correct as-is.
				if e.GetContent("KPEX_PASSKEY_PUB_KEY") != "" && e.GetContent(fido2.KPEXPasskeyFlagBE) == "" {
					r.issues = append(r.issues, doctorIssue{kind: "passkey-flags", entry: title, detail: "kpxcd-made passkey without KPEX_PASSKEY_FLAG_BE/BS; backfilled on next sign", fixable: false})
				}
				// legacy <KeeAgent> custom data
				for _, cd := range e.CustomData {
					if strings.EqualFold(cd.Key, sshagent.KeeAgentSettingsAttachment) && strings.Contains(cd.Value, "<KeeAgent>") {
						r.issues = append(r.issues, doctorIssue{kind: "keeagent-legacy", entry: title, detail: "legacy <KeeAgent> custom data; read compatibly, migrated on next kpxcd write", fixable: false})
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
					r.issues = append(r.issues, doctorIssue{kind: "ssh-marker", entry: title, detail: "private-key attachment with no kpxcd marker or KeeAgent settings; will not auto-load (use: kpxcctl ssh autoload)", fixable: false})
				}
			}
			visit(groups[gi].Groups)
		}
	}
	visit(db.Content.Root.Groups)
	return r, nil
}

// decodeVault opens and unlocks a vault file.
func decodeVault(path, password string) (*gokeepasslib.Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return nil, fmt.Errorf("cannot decode %s: %w", path, err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, err
	}
	return db, nil
}

// doctorFix rewrites oldPath into newPath preserving the vault header
// (KDF parameters, cipher, compression, KDBX version, metadata), rotating the
// per-save key material (MasterSeed/EncryptionIV/inner stream key) so versions
// of the NEW file cannot be XOR-combined with each other (old copies of the
// source remain combinable — purge those separately), optionally changing the
// password. No entry metadata is migrated — the daemon reads legacy forms and
// backfills flags on use. newPath must not exist; its directory must exist and
// is never chmodded.
func doctorFix(oldPath, oldPassword, newPath, newPassword string) (*doctorReport, error) {
	if _, err := os.Lstat(newPath); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing %s", newPath)
	}
	if _, err := os.Stat(filepath.Dir(newPath)); err != nil {
		return nil, fmt.Errorf("directory %s does not exist", filepath.Dir(newPath))
	}

	f, err := os.Open(oldPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	old := gokeepasslib.NewDatabase()
	old.Credentials = gokeepasslib.NewPasswordCredentials(oldPassword)
	if err := gokeepasslib.NewDecoder(f).Decode(old); err != nil {
		return nil, fmt.Errorf("cannot decode %s (wrong password, or keyfile/YubiKey vault): %w", oldPath, err)
	}
	if err := old.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("cannot unlock protected entries: %w", err)
	}

	rep, err := doctorCheck(oldPath, oldPassword)
	if err != nil {
		return nil, err
	}

	// Decode the source a second time into `want`: it stays untouched for
	// verification, while `old` gets mutated by encoding.
	want, err := decodeVault(oldPath, oldPassword)
	if err != nil {
		return nil, err
	}

	// Keep the source header wholesale (KDF, cipher, version); rotate the
	// per-save key material.
	newDB := gokeepasslib.NewDatabase()
	*newDB.Header = *old.Header
	fh := *old.Header.FileHeaders
	fh.MasterSeed = append([]byte{}, fh.MasterSeed...)
	fh.EncryptionIV = append([]byte{}, fh.EncryptionIV...)
	fh.ProtectedStreamKey = append([]byte{}, fh.ProtectedStreamKey...)
	fh.StreamStartBytes = append([]byte{}, fh.StreamStartBytes...)
	newDB.Header.FileHeaders = &fh
	newDB.Content = old.Content
	newDB.Credentials = gokeepasslib.NewPasswordCredentials(newPassword)
	if err := dbpool.RefreshCrypto(newDB); err != nil {
		return nil, err
	}
	if err := newDB.LockProtectedEntries(); err != nil {
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
	if err := gokeepasslib.NewEncoder(tmp).Encode(newDB); err != nil {
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

	// Verify before publishing: reopen the temp file with the new password
	// and compare structure with the source.
	if err := verifyRekey(tmpName, newPassword, want); err != nil {
		return nil, err
	}
	// Publish without clobbering: hard-link fails if the target appeared.
	if err := os.Link(tmpName, newPath); err != nil {
		return nil, err
	}

	rep.issues = append(rep.issues, doctorIssue{kind: "crypto", detail: fmt.Sprintf("key material rotated in %s; header/KDF preserved from source", newPath), fixable: false})
	return rep, nil
}

// verifyRekey reopens path with password and compares a canonical dump of it
// against want: group/entry UUIDs, every value's key+content+Protected flag,
// attachment names and bytes, custom data, history, deleted objects, recycle
// bin UUID. Any difference is an error; differing values are not printed.
func verifyRekey(path, password string, want *gokeepasslib.Database) error {
	chk, err := decodeVault(path, password)
	if err != nil {
		return fmt.Errorf("verify: fresh vault does not open with the new password: %w", err)
	}
	a, b := dumpVault(want), dumpVault(chk)
	if a != b {
		return fmt.Errorf("verify: content mismatch between source and rewritten vault")
	}
	return nil
}

func dumpVault(db *gokeepasslib.Database) string {
	var b strings.Builder
	if db.Content == nil || db.Content.Meta == nil || db.Content.Root == nil {
		return "<empty>"
	}
	// Compared: recycle-bin UUID, deleted objects, per group: UUID, name,
	// notes, custom data; per entry (current and history): UUID, every value's
	// key+content+Protected flag, attachment name+bytes (sha), custom data.
	fmt.Fprintf(&b, "recycle=%x\n", db.Content.Meta.RecycleBinUUID[:])
	for i := range db.Content.Root.DeletedObjects {
		fmt.Fprintf(&b, "del=%x\n", db.Content.Root.DeletedObjects[i].UUID[:])
	}
	dumpEntry := func(e *gokeepasslib.Entry) {
		fmt.Fprintf(&b, "entry=%x\n", e.UUID[:])
		for _, v := range e.Values {
			fmt.Fprintf(&b, "  v %q %q prot=%v\n", v.Key, v.Value.Content, v.Value.Protected.Bool)
		}
		for _, bn := range e.Binaries {
			content := []byte("<missing>")
			if bin := db.FindBinary(bn.Value.ID); bin != nil {
				if c, err := bin.GetContentBytes(); err == nil {
					content = c
				}
			}
			fmt.Fprintf(&b, "  bin %q len=%d sha=%x\n", bn.Name, len(content), sha256.Sum256(content))
		}
		for _, cd := range e.CustomData {
			fmt.Fprintf(&b, "  cd %q %q\n", cd.Key, cd.Value)
		}
	}
	var visit func(g *gokeepasslib.Group)
	visit = func(g *gokeepasslib.Group) {
		fmt.Fprintf(&b, "group=%x name=%q notes=%q\n", g.UUID[:], g.Name, g.Notes)
		for ei := range g.Entries {
			e := &g.Entries[ei]
			dumpEntry(e)
			for hi := range e.Histories {
				for _, he := range e.Histories[hi].Entries {
					dumpEntry(&he)
				}
			}
		}
		for gi := range g.Groups {
			visit(&g.Groups[gi])
		}
	}
	for i := range db.Content.Root.Groups {
		visit(&db.Content.Root.Groups[i])
	}
	return b.String()
}
