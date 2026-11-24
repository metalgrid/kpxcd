//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

// buildOldStyleVault writes a KDBX4 vault with legacy kpxcd passkey fields,
// legacy <KeeAgent> custom data, and a bare SSH-key attachment.
func buildOldStyleVault(t *testing.T, path, password string) {
	t.Helper()
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	// legacy passkey entry
	pk := gokeepasslib.NewEntry()
	pk.Values = append(pk.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "legacy-passkey"}},
		gokeepasslib.ValueData{Key: "KPEX_PASSKEY_RPID", Value: gokeepasslib.V{Content: "example.com"}},
		gokeepasslib.ValueData{Key: "KPEX_PASSKEY_HANDLE", Value: gokeepasslib.V{Content: "aGFuZGxl"}},
		gokeepasslib.ValueData{Key: "KPEX_PASSKEY_CRED_ID", Value: gokeepasslib.V{Content: "Y3JlZA"}},
		gokeepasslib.ValueData{Key: "KPEX_PASSKEY_PRIV_KEY", Value: gokeepasslib.V{Content: "pem", Protected: wrappers.BoolWrapper{Bool: true}}},
		gokeepasslib.ValueData{Key: "KPEX_PASSKEY_PUB_KEY", Value: gokeepasslib.V{Content: "YXNk"}},
		gokeepasslib.ValueData{Key: "KPEX_PASSKEY_COUNTER", Value: gokeepasslib.V{Content: "7"}},
	)

	// legacy keeagent + bare ssh key entry
	sk := gokeepasslib.NewEntry()
	sk.Values = append(sk.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "legacy-ssh"}})
	sk.CustomData = append(sk.CustomData, gokeepasslib.CustomData{
		Key:   "KeeAgent.settings",
		Value: `<KeeAgent><allowUseOfSshKey>true</allowUseOfSshKey><addAtDatabaseOpen>true</addAtDatabaseOpen><location><selectedType>attachment</selectedType><attachment>id_ed25519</attachment></location></KeeAgent>`,
	})
	bin := db.AddBinary([]byte("fake-key-bytes"))
	sk.Binaries = append(sk.Binaries, bin.CreateReference("id_ed25519"))

	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, pk, sk)
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorCheckAndFix(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.kdbx")
	newPath := filepath.Join(dir, "new.kdbx")
	buildOldStyleVault(t, oldPath, "oldpw")

	rep, err := doctorCheck(oldPath, "oldpw")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.issues) == 0 {
		t.Fatal("expected issues, got none")
	}
	t.Logf("check:\n%s", rep.String())

	if _, err := doctorFix(oldPath, "oldpw", newPath, "newpw"); err != nil {
		t.Fatal(err)
	}
	// refuse overwrite
	if _, err := doctorFix(oldPath, "oldpw", newPath, "newpw"); err == nil {
		t.Fatal("expected refusal to overwrite")
	}

	// fresh vault: opens with new password, old password fails, key material differs
	nf, err := os.Open(newPath)
	if err != nil {
		t.Fatal(err)
	}
	defer nf.Close()
	fresh := gokeepasslib.NewDatabase()
	fresh.Credentials = gokeepasslib.NewPasswordCredentials("newpw")
	if err := gokeepasslib.NewDecoder(nf).Decode(fresh); err != nil {
		t.Fatalf("fresh vault does not open with new password: %v", err)
	}
	if err := fresh.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	of, _ := os.Open(oldPath)
	old := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	old.Credentials = gokeepasslib.NewPasswordCredentials("oldpw")
	if err := gokeepasslib.NewDecoder(of).Decode(old); err != nil {
		t.Fatal(err)
	}
	if string(fresh.Header.FileHeaders.MasterSeed) == string(old.Header.FileHeaders.MasterSeed) {
		t.Error("MasterSeed not rotated")
	}
	if string(fresh.Header.FileHeaders.EncryptionIV) == string(old.Header.FileHeaders.EncryptionIV) {
		t.Error("EncryptionIV not rotated")
	}
	if string(fresh.Content.InnerHeader.InnerRandomStreamKey) == string(old.Content.InnerHeader.InnerRandomStreamKey) {
		t.Error("inner stream key not rotated")
	}
	// D1: KDF parameters must be preserved, not reset to library defaults
	if fresh.Header.FileHeaders.KdfParameters.Memory != old.Header.FileHeaders.KdfParameters.Memory ||
		fresh.Header.FileHeaders.KdfParameters.Iterations != old.Header.FileHeaders.KdfParameters.Iterations {
		t.Error("KDF parameters not preserved")
	}
	if fresh.Header.FileHeaders.CipherID == nil || string(fresh.Header.FileHeaders.CipherID) != string(old.Header.FileHeaders.CipherID) {
		t.Error("cipher not preserved")
	}
	// D6: directory mode must not change
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("directory mode changed to %o", fi.Mode().Perm())
	}

	// entries migrated
	var pkEntry, skEntry *gokeepasslib.Entry
	for gi := range fresh.Content.Root.Groups {
		for ei := range fresh.Content.Root.Groups[gi].Entries {
			e := &fresh.Content.Root.Groups[gi].Entries[ei]
			switch e.GetTitle() {
			case "legacy-passkey":
				pkEntry = e
			case "legacy-ssh":
				skEntry = e
			}
		}
	}
	if pkEntry == nil || skEntry == nil {
		t.Fatal("entries not copied")
	}
	// No migrations: legacy fields stay as-is (daemon reads them compatibly).
	if pkEntry.GetContent("KPEX_PASSKEY_RPID") != "example.com" {
		t.Error("legacy passkey fields must be preserved, not rewritten")
	}
	if pkEntry.GetContent("KPEX_PASSKEY_COUNTER") != "7" {
		t.Error("counter not preserved")
	}
	if skEntry.GetContent("KPXCD_SSH_KEY") != "" {
		t.Error("bare key must NOT be auto-marked (D2)")
	}
	if len(skEntry.CustomData) == 0 {
		t.Error("legacy custom data must be preserved (D3)")
	}
}

func TestDoctorFixKDBX3(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old31.kdbx")
	newPath := filepath.Join(dir, "new31.kdbx")
	db := gokeepasslib.NewDatabase() // KDBX 3.1
	db.Credentials = gokeepasslib.NewPasswordCredentials("pw")
	e := gokeepasslib.NewEntry()
	e.Values = append(e.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "s"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "v", Protected: wrappers.BoolWrapper{Bool: true}}})
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, e)
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Create(oldPath)
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if _, err := doctorFix(oldPath, "pw", newPath, "pw2"); err != nil {
		t.Fatalf("KDBX3 --fix failed (D7): %v", err)
	}
	nf, _ := os.Open(newPath)
	defer nf.Close()
	chk := gokeepasslib.NewDatabase()
	chk.Credentials = gokeepasslib.NewPasswordCredentials("pw2")
	if err := gokeepasslib.NewDecoder(nf).Decode(chk); err != nil {
		t.Fatal(err)
	}
	if chk.Header.IsKdbx4() {
		t.Error("KDBX3 vault must stay KDBX3")
	}
	if err := chk.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	for _, en := range chk.Content.Root.Groups[0].Entries {
		if en.GetTitle() == "s" && en.GetPassword() != "v" {
			t.Errorf("protected value mismatch after KDBX3 rekey: %q", en.GetPassword())
		}
	}
}

func TestDoctorFixEmptyProtectedPassword(t *testing.T) {
	// V1: an entry with an empty protected Password is ordinary (passkeys,
	// notes) and must not fail verification.
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.kdbx")
	newPath := filepath.Join(dir, "new.kdbx")
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = gokeepasslib.NewPasswordCredentials("pw")
	e := gokeepasslib.NewEntry()
	e.Values = append(e.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "note"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "", Protected: wrappers.BoolWrapper{Bool: true}}})
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, e)
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Create(oldPath)
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := doctorFix(oldPath, "pw", newPath, "pw"); err != nil {
		t.Fatalf("V1: empty protected password must not fail: %v", err)
	}
}

func targetEntry(d *gokeepasslib.Database) *gokeepasslib.Entry {
	for gi := range d.Content.Root.Groups {
		for ei := range d.Content.Root.Groups[gi].Entries {
			if d.Content.Root.Groups[gi].Entries[ei].GetTitle() == "t" {
				return &d.Content.Root.Groups[gi].Entries[ei]
			}
		}
	}
	return nil
}

func TestVerifyRekeyDetectsTampering(t *testing.T) {
	// T1: encode ONE vault, then decode-mutate-reencode per case so only the
	// mutation differs (UUIDs stay identical).
	dir := t.TempDir()
	base := filepath.Join(dir, "base.kdbx")
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = gokeepasslib.NewPasswordCredentials("pw")
	e := gokeepasslib.NewEntry()
	e.Values = append(e.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "t"}})
	h := gokeepasslib.History{}
	he := gokeepasslib.NewEntry()
	he.Values = append(he.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "t-old"}})
	h.Entries = append(h.Entries, he)
	e.Histories = append(e.Histories, h)
	e.Binaries = append(e.Binaries, db.AddBinary([]byte("attachment-bytes")).CreateReference("a"))
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, e)
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Create(base)
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	f.Close()

	want, err := decodeVault(base, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRekey(base, "pw", want); err != nil {
		t.Fatalf("identical vault must verify: %v", err)
	}

	cases := map[string]func(*gokeepasslib.Database){
		"changed entry UUID": func(d *gokeepasslib.Database) { targetEntry(d).UUID = gokeepasslib.NewUUID() },
		"changed attachment byte": func(d *gokeepasslib.Database) {
			targetEntry(d).Binaries[0] = d.AddBinary([]byte("tampered")).CreateReference("a")
		},
		"dropped history": func(d *gokeepasslib.Database) { targetEntry(d).Histories = nil },
		"changed value":   func(d *gokeepasslib.Database) { targetEntry(d).Values[0].Value.Content = "changed" },
		"changed history value": func(d *gokeepasslib.Database) {
			targetEntry(d).Histories[0].Entries[0].Values[0].Value.Content = "changed-old"
		},
	}
	for name, mutate := range cases {
		d, err := decodeVault(base, "pw")
		if err != nil {
			t.Fatal(err)
		}
		// find our entry by title (the root group has a placeholder entry)
		var target *gokeepasslib.Entry
		for gi := range d.Content.Root.Groups {
			for ei := range d.Content.Root.Groups[gi].Entries {
				if d.Content.Root.Groups[gi].Entries[ei].GetTitle() == "t" {
					target = &d.Content.Root.Groups[gi].Entries[ei]
				}
			}
		}
		if target == nil {
			t.Fatal("entry not found")
		}
		mutate(d)
		if err := d.LockProtectedEntries(); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "tampered.kdbx")
		of, _ := os.Create(out)
		if err := gokeepasslib.NewEncoder(of).Encode(d); err != nil {
			t.Fatal(err)
		}
		of.Close()
		if err := verifyRekey(out, "pw", want); err == nil {
			t.Errorf("verifyRekey accepted tampered vault: %s", name)
		}
	}
	if err := verifyRekey(base, "wrong", want); err == nil {
		t.Error("verifyRekey accepted wrong password")
	}
}
