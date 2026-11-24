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
	if !rep.hasFixable() {
		t.Fatalf("expected fixable issues, got:\n%s", rep.String())
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
		t.Error("MasterSeed reused between old and fresh vault")
	}
	if string(fresh.Header.FileHeaders.EncryptionIV) == string(old.Header.FileHeaders.EncryptionIV) {
		t.Error("EncryptionIV reused")
	}
	if string(fresh.Content.InnerHeader.InnerRandomStreamKey) == string(old.Content.InnerHeader.InnerRandomStreamKey) {
		t.Error("inner stream key reused")
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
	if pkEntry.GetContent("KPEX_PASSKEY_RELYING_PARTY") != "example.com" {
		t.Error("passkey RPID not migrated to KeePassXC name")
	}
	if pkEntry.GetContent("KPEX_PASSKEY_RPID") != "" {
		t.Error("legacy RPID field not removed")
	}
	if pkEntry.GetContent("KPEX_PASSKEY_FLAG_BE") != "0" {
		t.Error("BE flag not backfilled")
	}
	if pkEntry.GetContent("KPEX_PASSKEY_COUNTER") != "7" {
		t.Error("counter not preserved")
	}
	if skEntry.GetContent("KPXCD_SSH_KEY") == "" && len(skEntry.CustomData) == 0 {
		// legacy custom data should be converted to an attachment
	}
	hasSettingsAttachment := false
	for _, b := range skEntry.Binaries {
		if b.Name == "KeeAgent.settings" {
			hasSettingsAttachment = true
		}
	}
	if !hasSettingsAttachment {
		t.Error("legacy KeeAgent custom data not converted to EntrySettings attachment")
	}
	if len(skEntry.CustomData) != 0 {
		t.Error("legacy custom data not removed")
	}
}
