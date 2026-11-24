//go:build linux

package fido2

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2/hid"
	"github.com/metalgrid/kpxcd/internal/security"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

var _ = Describe("Step 5 resident storage", func() {
	var pool *dbpool.DatabasePool
	var path, uuid string
	var svc *Fido2Service
	var store *CtapStore
	var target *dbpool.OpenDatabase
	create := func(rp string, handle []byte, resident bool) []byte {
		id, _, _, err := store.Create(rp, "RP", "alice", "Alice", handle, resident)
		Expect(err).NotTo(HaveOccurred())
		return id
	}
	refs := func() []hid.CredentialReference {
		result, err := store.ResidentCredentials("example.com")
		Expect(err).NotTo(HaveOccurred())
		return result
	}
	addDB := func() (string, string) {
		other, otherPath := newTestPoolWithDB()
		Expect(other.Close()).To(Succeed())
		password, err := security.NewSecureString("testpassword")
		Expect(err).NotTo(HaveOccurred())
		defer password.Destroy()
		otherUUID, err := pool.Open(otherPath, dbpool.PasswordCredential(password))
		Expect(err).NotTo(HaveOccurred())
		return otherUUID, otherPath
	}
	BeforeEach(func() {
		pool, path = newTestPoolWithDB()
		DeferCleanup(pool.Close)
		uuid = firstPoolUUID(pool)
		var err error
		target, err = pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())
		svc = NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		store = NewCtapStore(svc, pool, path)
	})
	It("replaces only the exact decoded account while preserving the entry and unrelated fields", func() {
		oldID := create("example.com", []byte{0}, false)
		otherID := create("example.com", []byte{1}, false)
		original, err := svc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(oldID))
		Expect(err).NotTo(HaveOccurred())
		Expect(target.UpdateAndSave(func(db *gokeepasslib.Database) error {
			entry := findEntryByUUIDHex(&db.Content.Root.Groups, original.EntryUUID)
			entry.Times.CreationTime = &wrappers.TimeWrapper{Time: time.Unix(100, 0)}
			setEntryValue(entry, "Title", "Imported login", false)
			setEntryValue(entry, "Password", "keep password", true)
			setEntryValue(entry, "Notes", "keep notes", false)
			setEntryValue(entry, "custom", "keep custom", false)
			// Alternate unused trailing base64 bits decode to the exact same byte.
			setEntryValue(entry, KPEXPasskeyHandle, "AB", false)
			return nil
		})).To(Succeed())
		replacement := create("example.com", []byte{0}, true)
		Expect(replacement).NotTo(Equal(oldID))
		Expect(refs()).To(HaveLen(2))
		saved, err := svc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(replacement))
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.EntryUUID).To(Equal(original.EntryUUID))
		Expect(saved.PrivateKeyPEM).NotTo(Equal(original.PrivateKeyPEM))
		Expect(saved.SignCount).To(BeZero())
		for _, entry := range svc.passkeySnapshot(target) {
			if fmt.Sprintf("%x", entry.UUID[:]) == original.EntryUUID {
				Expect(entry.Times.CreationTime.Time).To(Equal(time.Unix(100, 0)))
				Expect(entry.GetTitle()).To(Equal("Imported login"))
				Expect(entry.GetContent("Password")).To(Equal("keep password"))
				Expect(entry.GetContent("Notes")).To(Equal("keep notes"))
				Expect(entry.GetContent("custom")).To(Equal("keep custom"))
			}
		}
		_, err = svc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(otherID))
		Expect(err).NotTo(HaveOccurred())
		reopened := reopenPool(path)
		DeferCleanup(reopened.Close)
		saved, err = NewFido2Service(&config.Fido2Config{Enabled: true}, reopened).FindPasskeyByCredentialID(saved.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.EntryUUID).To(Equal(original.EntryUUID))
	})
	DescribeTable("does not infer identity from account names or another RP", func(rp string, handle []byte) {
		old := create(rp, handle, false)
		create("example.com", []byte{0}, true)
		_, err := svc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(old))
		Expect(err).NotTo(HaveOccurred())
		all, err := svc.FindPasskeysByRPID("", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(all).To(HaveLen(2))
	}, Entry("same name different account", "example.com", []byte{1}), Entry("same account bytes different RP", "other.example", []byte{0}))
	It("does not replace when rk is false", func() {
		create("example.com", []byte{0}, false)
		create("example.com", []byte{0}, false)
		Expect(refs()).To(HaveLen(2))
	})
	It("refuses multiple matches in the selected database without mutation", func() {
		create("example.com", []byte{0}, false)
		create("example.com", []byte{0}, false)
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		_, _, _, err = store.Create("example.com", "", "", "", []byte{0}, true)
		Expect(err).To(MatchError(ContainSubstring("ambiguous")))
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
		Expect(refs()).To(HaveLen(2))
	})
	DescribeTable("refuses visible cross-database matches", func(local bool) {
		other, otherPath := addDB()
		_, err := svc.CreatePasskeyWithUserHandle(other, "example.com", "", "", "", []byte{0}, nil)
		Expect(err).NotTo(HaveOccurred())
		if local {
			create("example.com", []byte{0}, false)
		}
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		otherBefore, err := os.ReadFile(otherPath)
		Expect(err).NotTo(HaveOccurred())
		_, _, _, err = store.Create("example.com", "", "", "", []byte{0}, true)
		Expect(err).To(MatchError(ContainSubstring("ambiguous")))
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
		otherAfter, err := os.ReadFile(otherPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(otherAfter).To(Equal(otherBefore))
	}, Entry("unique match elsewhere", false), Entry("matches in both files", true))
	It("allows unrelated locked databases and leaves hidden matches untouched", func() {
		other, otherPath := addDB()
		_, err := svc.CreatePasskeyWithUserHandle(other, "example.com", "", "", "", []byte{0}, nil)
		Expect(err).NotTo(HaveOccurred())
		before, err := os.ReadFile(otherPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(pool.Lock(other)).To(Succeed())
		create("example.com", []byte{0}, true)
		Expect(refs()).To(HaveLen(1))
		after, err := os.ReadFile(otherPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	})
	DescribeTable("requires an available selected destination with no arbitrary fallback", func(mode string) {
		addDB()
		selected := path
		switch mode {
		case "empty":
			selected = ""
		case "missing":
			selected = filepath.Join(GinkgoT().TempDir(), "missing.kdbx")
		case "locked":
			Expect(pool.Lock(uuid)).To(Succeed())
		}
		_, _, _, err := NewCtapStore(svc, pool, selected).Create("example.com", "", "", "", []byte{0}, true)
		Expect(err).To(HaveOccurred())
		all, err := svc.FindPasskeysByRPID("", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(all).To(BeEmpty())
	}, Entry("empty", "empty"), Entry("missing", "missing"), Entry("locked", "locked"))
	DescribeTable("refuses stale destination instances without changing either file", func(copied bool) {
		selected, err := store.defaultDB()
		Expect(err).NotTo(HaveOccurred())
		replacementPath := path
		if copied {
			replacementPath = filepath.Join(GinkgoT().TempDir(), "copy.kdbx")
			data, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(os.WriteFile(replacementPath, data, 0600)).To(Succeed())
		}
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		// Lock first to bound watcher cleanup; Open still replaces the same UUID.
		Expect(pool.Lock(uuid)).To(Succeed())
		password, err := security.NewSecureString("testpassword")
		Expect(err).NotTo(HaveOccurred())
		defer password.Destroy()
		reopened, err := pool.Open(replacementPath, dbpool.PasswordCredential(password))
		Expect(err).NotTo(HaveOccurred())
		Expect(reopened).To(Equal(uuid))
		_, err = svc.createPasskey(selected, "example.com", "", "", "", []byte{0}, nil, true)
		Expect(err).To(MatchError(ContainSubstring("unavailable")))
		for _, file := range []string{path, replacementPath} {
			after, err := os.ReadFile(file)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before))
		}
	}, Entry("copied vault", true), Entry("same path reopened", false))
	DescribeTable("refuses conflicting attributes committed by an independent content writer before registration", func(other bool) {
		create("example.com", []byte{0}, false)
		writerDB := target
		if other {
			id, _ := addDB()
			var err error
			writerDB, err = pool.Get(id)
			Expect(err).NotTo(HaveOccurred())
		}
		// An arbitrary attribute writer can introduce a complete same-account entry,
		// without taking the FIDO service mutex, just like Secret Service.
		var entry gokeepasslib.Entry
		for _, candidate := range svc.passkeySnapshot(target) {
			if candidate.GetContent(KPEXPasskeyRPID) == "example.com" {
				entry = candidate
			}
		}
		Expect(entry.GetContent(KPEXPasskeyRPID)).To(Equal("example.com"))
		done := make(chan error, 1)
		go func() {
			done <- writerDB.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
				copy := entry.Clone()
				kdb.Content.Root.Groups[0].Entries = append(kdb.Content.Root.Groups[0].Entries, copy)
				return nil
			})
		}()
		Eventually(done, 5*time.Second).Should(Receive(Succeed()))
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		_, _, _, err = store.Create("example.com", "", "", "", []byte{0}, true)
		Expect(err).To(MatchError(ContainSubstring("ambiguous")))
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	}, Entry("target database", false), Entry("other unlocked database", true))
	It("normalizes configured path components deterministically", func() {
		selected := filepath.Dir(path) + "/unused/../" + filepath.Base(path)
		_, _, _, err := NewCtapStore(svc, pool, selected).Create("example.com", "", "", "", []byte{0}, true)
		Expect(err).NotTo(HaveOccurred())
	})
	It("keeps imported material outside explicit eligible replacement unchanged and import append-only", func() {
		_, key, err := generateKeyPair(COSEAlgES256)
		Expect(err).NotTo(HaveOccurred())
		in := ImportPasskeyInput{RPID: "example.com", CredentialID: "AQ", UserHandle: "Ag", PrivateKeyPEM: key, SignCount: 17}
		_, err = svc.ImportPasskey(uuid, in)
		Expect(err).NotTo(HaveOccurred())
		create("example.com", []byte{0}, true)
		saved, err := svc.FindPasskeyByCredentialID(in.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.PrivateKeyPEM).To(Equal(key))
		Expect(saved.UserHandle).To(Equal(in.UserHandle))
		Expect(saved.SignCount).To(Equal(in.SignCount))
		in.CredentialID = "Aw"
		_, err = svc.ImportPasskey(uuid, in)
		Expect(err).NotTo(HaveOccurred())
		Expect(refs()).To(HaveLen(3))
		_, _, _, err = store.Create("example.com", "", "", "", []byte{2}, true)
		Expect(err).To(MatchError(ContainSubstring("ambiguous")))
	})
	DescribeTable("returns no replacement or signature on save failure and retains in-memory identity", func(conflict bool) {
		old := create("example.com", []byte{0}, false)
		original := refs()[0]
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		if conflict {
			target.Fingerprint = dbpool.FileFingerprint{}
		} else {
			file, err := os.Open(path)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(file.Close)
			target.Path = fmt.Sprintf("/proc/self/fd/%d", file.Fd())
		}
		_, err = svc.createPasskey(target, "example.com", "", "", "", []byte{0}, nil, true)
		Expect(err).To(HaveOccurred())
		result, err := store.AssertResident(original, []hid.CredentialReference{original}, make([]byte, 32), true, true)
		Expect(err).To(HaveOccurred())
		Expect(result.Signature).To(BeEmpty())
		Expect(refs()).To(Equal([]hid.CredentialReference{original}))
		saved, err := svc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(old))
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.SignCount).To(BeZero())
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	}, Entry("pre-mutation conflict", true), Entry("post-mutation atomic save failure", false))
	It("serializes concurrent same-account resident registrations into one entry", func() {
		var wg sync.WaitGroup
		errs := make(chan error, 12)
		for range 12 {
			wg.Go(func() { _, _, _, err := store.Create("example.com", "", "", "", []byte{0}, true); errs <- err })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(refs()).To(HaveLen(1))
	})
	DescribeTable("serializes resident creation across independent service instances", func(differentTarget bool) {
		secondPath := path
		if differentTarget {
			_, secondPath = addDB()
		}
		second := NewCtapStore(NewFido2Service(&config.Fido2Config{Enabled: true}, pool), pool, secondPath)
		start := make(chan struct{})
		done := make(chan error, 2)
		for _, writer := range []*CtapStore{store, second} {
			go func() {
				<-start
				_, _, _, err := writer.Create("example.com", "", "", "", []byte{0}, true)
				done <- err
			}()
		}
		close(start)
		failures := 0
		for range 2 {
			var err error
			Eventually(done, 5*time.Second).Should(Receive(&err))
			if err != nil {
				Expect(err).To(MatchError(ContainSubstring("ambiguous")))
				failures++
			}
		}
		if differentTarget {
			Expect(failures).To(Equal(1))
		} else {
			Expect(failures).To(BeZero())
		}
		Expect(refs()).To(HaveLen(1))
	}, Entry("same target", false), Entry("different targets", true))
	It("serializes an import racing resident registration without discarding imported material", func() {
		_, key, err := generateKeyPair(COSEAlgES256)
		Expect(err).NotTo(HaveOccurred())
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Go(func() { _, _, _, err := store.Create("example.com", "", "", "", []byte{0}, true); errs <- err })
		wg.Go(func() {
			_, err := svc.ImportPasskey(uuid, ImportPasskeyInput{RPID: "example.com", CredentialID: "AQ", UserHandle: "Ag", PrivateKeyPEM: key})
			errs <- err
		})
		wg.Wait()
		close(errs)
		for err := range errs {
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(refs()).To(HaveLen(2))
		imported, err := svc.FindPasskeyByCredentialID("AQ")
		Expect(err).NotTo(HaveOccurred())
		Expect(imported.PrivateKeyPEM).To(Equal(key))
	})
	It("orders newest-created candidates first with deterministic UUID ties", func() {
		create("example.com", []byte{0}, false)
		create("example.com", []byte{1}, false)
		create("example.com", []byte{2}, false)
		oldRefs := refs()
		newest := oldRefs[0]
		now := wrappers.TimeWrapper{Time: time.Unix(100, 0)}
		Expect(target.UpdateAndSave(func(db *gokeepasslib.Database) error {
			for _, ref := range oldRefs {
				entry := findEntryByUUIDHex(&db.Content.Root.Groups, ref.EntryUUID)
				entry.Times.CreationTime = &now
				setEntryValue(entry, KPEXPasskeyCreated, "", false)
			}
			findEntryByUUIDHex(&db.Content.Root.Groups, newest.EntryUUID).Times.CreationTime = &wrappers.TimeWrapper{Time: time.Unix(200, 0)}
			return nil
		})).To(Succeed())
		ordered := refs()
		Expect(ordered[0]).To(Equal(newest))
		Expect(ordered[1].EntryUUID < ordered[2].EntryUUID).To(BeTrue())
		Expect(refs()).To(Equal(ordered))
	})
	DescribeTable("revalidates exact continuation identity and refuses without a counter advance", func(change string) {
		create("example.com", []byte{0}, false)
		ref := refs()[0]
		switch change {
		case "lock":
			Expect(pool.Lock(uuid)).To(Succeed())
		case "reopen":
			Expect(pool.Lock(uuid)).To(Succeed())
			password, err := security.NewSecureString("testpassword")
			Expect(err).NotTo(HaveOccurred())
			defer password.Destroy()
			_, err = pool.Open(path, dbpool.PasswordCredential(password))
			Expect(err).NotTo(HaveOccurred())
		case "replacement":
			create("example.com", []byte{0}, true)
		case "remove":
			Expect(svc.RemovePasskey(ref.CredentialID)).To(Succeed())
		default:
			Expect(target.UpdateAndSave(func(db *gokeepasslib.Database) error {
				entry := findEntryByUUIDHex(&db.Content.Root.Groups, ref.EntryUUID)
				key := map[string]string{"rp": KPEXPasskeyRPID, "id": KPEXPasskeyCredID, "handle": KPEXPasskeyHandle}[change]
				setEntryValue(entry, key, "other", false)
				return nil
			})).To(Succeed())
		}
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		result, err := store.AssertResident(ref, []hid.CredentialReference{ref}, make([]byte, 32), true, true)
		Expect(err).To(HaveOccurred())
		Expect(result.Signature).To(BeEmpty())
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	}, Entry("locked", "lock"), Entry("lock unlock new instance", "reopen"), Entry("replaced", "replacement"), Entry("removed", "remove"), Entry("RP changed", "rp"), Entry("ID changed", "id"), Entry("handle changed", "handle"))
	It("refuses an initial resident assertion when another enumerated account has changed", func() {
		for i := range 3 {
			create("example.com", []byte{byte(i)}, false)
		}
		original := refs()
		independent := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		Expect(independent.RemovePasskey(original[2].CredentialID)).To(Succeed())
		result, err := store.AssertResident(original[0], original, make([]byte, 32), true, true)
		Expect(err).To(HaveOccurred())
		Expect(result.Signature).To(BeEmpty())
		saved, err := svc.FindPasskeyByCredentialID(original[0].CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.SignCount).To(BeZero())
	})
	DescribeTable("refuses the full series when a nonselected original changes before the atomic boundary", func(which int, change string) {
		create("example.com", []byte{0}, false)
		for i := 1; i < 3; i++ {
			_, otherPath := addDB()
			_, _, _, err := NewCtapStore(svc, pool, otherPath).Create("example.com", "", "", "", []byte{byte(i)}, false)
			Expect(err).NotTo(HaveOccurred())
		}
		original := refs()
		Expect(original).To(HaveLen(3))
		first, err := store.AssertResident(original[0], original, make([]byte, 32), true, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Signature).NotTo(BeEmpty())
		changed := original[which]
		db, err := pool.Get(changed.DatabaseUUID)
		Expect(err).NotTo(HaveOccurred())
		// This writer has no shared FIDO service mutation mutex.
		independent := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		switch change {
		case "lock", "reopen":
			Expect(pool.Lock(db.UUID)).To(Succeed())
			if change == "reopen" {
				password, err := security.NewSecureString("testpassword")
				Expect(err).NotTo(HaveOccurred())
				defer password.Destroy()
				_, err = pool.Open(db.Path, dbpool.PasswordCredential(password))
				Expect(err).NotTo(HaveOccurred())
			}
		case "remove":
			Expect(independent.RemovePasskey(changed.CredentialID)).To(Succeed())
		case "replace":
			handle, err := base64.RawURLEncoding.DecodeString(changed.UserHandle)
			Expect(err).NotTo(HaveOccurred())
			_, _, _, err = NewCtapStore(independent, pool, db.Path).Create("example.com", "", "", "", handle, true)
			Expect(err).NotTo(HaveOccurred())
		case "writer":
			Expect(db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
				setEntryValue(findEntryByUUIDHex(&kdb.Content.Root.Groups, changed.EntryUUID), KPEXPasskeyHandle, "changed", false)
				return nil
			})).To(Succeed())
		}
		selected, err := pool.Get(original[1].DatabaseUUID)
		Expect(err).NotTo(HaveOccurred())
		before, err := os.ReadFile(selected.Path)
		Expect(err).NotTo(HaveOccurred())
		result, err := store.AssertResident(original[1], original, make([]byte, 32), true, true)
		Expect(err).To(HaveOccurred())
		Expect(result.Signature).To(BeEmpty())
		saved, err := svc.FindPasskeyByCredentialID(original[1].CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.SignCount).To(BeZero())
		after, err := os.ReadFile(selected.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	}, Entry("already returned locked", 0, "lock"), Entry("later locked", 2, "lock"),
		Entry("already returned reopened", 0, "reopen"), Entry("later reopened", 2, "reopen"),
		Entry("already returned removed", 0, "remove"), Entry("later removed", 2, "remove"),
		Entry("already returned replaced", 0, "replace"), Entry("later replaced", 2, "replace"),
		Entry("already returned independently edited", 0, "writer"), Entry("later independently edited", 2, "writer"))
	It("never falls back to another database with the same credential ID", func() {
		create("example.com", []byte{0}, false)
		ref := refs()[0]
		other, _ := addDB()
		old, err := svc.FindPasskeyByCredentialID(ref.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		// Simulate a copied vault entry without using Import's intentional duplicate refusal.
		otherDB, err := pool.Get(other)
		Expect(err).NotTo(HaveOccurred())
		Expect(persistPasskey(otherDB, old)).To(Succeed())
		Expect(pool.Lock(uuid)).To(Succeed())
		result, err := store.AssertResident(ref, []hid.CredentialReference{ref}, make([]byte, 32), true, true)
		Expect(err).To(HaveOccurred())
		Expect(result.Signature).To(BeEmpty())
		copy, err := svc.FindPasskeyByCredentialID(ref.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(copy.SignCount).To(BeZero())
	})
	It("refuses an exhausted targeted assertion without a signature or counter change", func() {
		create("example.com", []byte{0}, false)
		ref := refs()[0]
		Expect(target.UpdateAndSave(func(db *gokeepasslib.Database) error {
			setEntryValue(findEntryByUUIDHex(&db.Content.Root.Groups, ref.EntryUUID), KPEXPasskeyCounter, "4294967295", false)
			return nil
		})).To(Succeed())
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		result, err := store.AssertResident(ref, []hid.CredentialReference{ref}, make([]byte, 32), true, true)
		Expect(err).To(MatchError(ContainSubstring("counter exhausted")))
		Expect(result.Signature).To(BeEmpty())
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	})

	It("serializes targeted signing against same-account replacement", func() {
		create("example.com", []byte{0}, false)
		ref := refs()[0]
		var wg sync.WaitGroup
		var signed hid.ResidentAssertion
		var signErr, createErr error
		wg.Go(func() {
			signed, signErr = store.AssertResident(ref, []hid.CredentialReference{ref}, make([]byte, 32), true, true)
		})
		wg.Go(func() { _, _, _, createErr = store.Create("example.com", "", "", "", []byte{0}, true) })
		wg.Wait()
		Expect(createErr).NotTo(HaveOccurred())
		if signErr == nil {
			originalID, err := base64.RawURLEncoding.DecodeString(ref.CredentialID)
			Expect(err).NotTo(HaveOccurred())
			Expect(signed.CredentialID).To(Equal(originalID))
		} else {
			Expect(signed.Signature).To(BeEmpty())
		}
		current := refs()
		Expect(current).To(HaveLen(1))
		Expect(current[0].CredentialID).NotTo(Equal(ref.CredentialID))
		saved, err := svc.FindPasskeyByCredentialID(current[0].CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.SignCount).To(BeZero())
	})

	DescribeTable("returns identifying account information only after actual UV", func(uv bool) {
		create("example.com", []byte{0}, true)
		ref := refs()[0]
		result, err := store.AssertResident(ref, []hid.CredentialReference{ref}, make([]byte, 32), true, uv)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.UserHandle).To(Equal([]byte{0}))
		pk, err := svc.FindPasskeyByCredentialID(ref.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode([]byte(pk.PrivateKeyPEM))
		Expect(block).NotTo(BeNil())
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		digest := sha256.Sum256(append(append([]byte(nil), result.AuthData...), make([]byte, 32)...))
		Expect(ecdsa.VerifyASN1(&key.(*ecdsa.PrivateKey).PublicKey, digest[:], result.Signature)).To(BeTrue())
		if uv {
			Expect(result.Name).To(Equal("alice"))
			Expect(result.DisplayName).To(Equal("Alice"))
		} else {
			Expect(result.Name).To(BeEmpty())
			Expect(result.DisplayName).To(BeEmpty())
		}
	}, Entry("verified", true), Entry("unverified", false))
})

var _ = Describe("assertResident counterless foreign entry (Z1)", func() {
	It("signs with counter 0 and leaves the file bytes unchanged", func() {
		pool, path := newTestPoolWithDB()
		// Replace the default entry with a KeePassXC-style one: no PUB_KEY,
		// no counter, BE/BS flags set.
		odb, err := pool.Get(firstPoolUUID(pool))
		Expect(err).NotTo(HaveOccurred())
		pk := &PasskeyEntry{
			RPID: "example.com", Username: "u", UserHandle: "aGFuZGxl", CredentialID: "Y3JlZA",
			PrivateKeyPEM: testPrivPEM,
		}
		e := newPasskeyEntry(pk)
		for _, key := range []string{KPEXPasskeyPubKey, KPEXPasskeyCounter} {
			if idx := e.GetIndex(key); idx >= 0 {
				e.Values = append(e.Values[:idx], e.Values[idx+1:]...)
			}
		}
		setEntryValue(&e, KPEXPasskeyFlagBE, "1", false)
		setEntryValue(&e, KPEXPasskeyFlagBS, "1", false)
		Expect(odb.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
			kdb.Content.Root.Groups[0].Entries = []gokeepasslib.Entry{e}
			return nil
		})).To(Succeed())

		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())

		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		refs, err := svc.residentCredentials("example.com")
		Expect(err).NotTo(HaveOccurred())
		Expect(refs).To(HaveLen(1))

		hash := sha256.Sum256([]byte("cd"))
		res, err := svc.assertResident(refs[0], refs, hash[:], true, false)
		Expect(err).NotTo(HaveOccurred(), "counterless foreign entry must sign, not ErrSkipSave")
		Expect(res.Signature).NotTo(BeEmpty())
		Expect(res.AuthData[32] & (FlagBE | FlagBS)).To(Equal(byte(FlagBE | FlagBS)))
		Expect(binary.BigEndian.Uint32(res.AuthData[33:37])).To(Equal(uint32(0)), "counter must be 0")

		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "counterless sign must not rewrite the vault")
	})
})
