//go:build linux

package dbpool

import (
	"encoding/xml"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/metalgrid/kpxcd/internal/security"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tobischo/gokeepasslib/v3"
)

var _ = Describe("Step 5 atomic ownership boundary", func() {
	DescribeTable("holds content writers and pool lifecycle outside the check/save gap", func(writeTarget, reopen bool) {
		pool, uuid, target := openTestKDBX("target.kdbx", "password", nil, nil)
		otherPath := createTestKDBX(GinkgoT().TempDir(), "other.kdbx", "password", nil)
		password, err := security.NewSecureString("password")
		Expect(err).NotTo(HaveOccurred())
		defer password.Destroy()
		otherID, err := pool.Open(otherPath, PasswordCredential(password))
		Expect(err).NotTo(HaveOccurred())
		other, err := pool.Get(otherID)
		Expect(err).NotTo(HaveOccurred())
		writerDB := other
		if writeTarget {
			writerDB = target
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		atomicDone := make(chan error, 1)
		go func() {
			atomicDone <- pool.UpdateAndSaveWithUnlockedDatabases(target, func(dbs map[*OpenDatabase]*gokeepasslib.Database) error {
				close(entered)
				select {
				case <-release:
				case <-time.After(5 * time.Second):
					return fmt.Errorf("test release timed out")
				}
				dbs[target].Content.Root.Groups[0].Name = "registration committed"
				return nil
			})
		}()
		Eventually(entered, 5*time.Second).Should(BeClosed())
		// These nonblocking lock attempts prove exclusion, not elapsed scheduling time.
		targetWritable := target.mu.TryLock()
		if targetWritable {
			target.mu.Unlock()
		}
		otherWritable := other.mu.TryLock()
		if otherWritable {
			other.mu.Unlock()
		}
		poolWritable := pool.mu.TryLock()
		if poolWritable {
			pool.mu.Unlock()
		}
		otherReadable := other.mu.TryRLock()
		if otherReadable {
			other.mu.RUnlock()
		}
		Expect(targetWritable).To(BeFalse())
		Expect(otherWritable).To(BeFalse())
		Expect(poolWritable).To(BeFalse())
		Expect(otherReadable).To(BeTrue(), "unrelated readers remain concurrent")
		writerStarted, lifecycleStarted := make(chan struct{}), make(chan struct{})
		writerEntered := make(chan struct{})
		writerDone, lifecycleDone := make(chan error, 1), make(chan error, 1)
		go func() {
			close(writerStarted)
			writerDone <- writerDB.UpdateAndSave(func(db *gokeepasslib.Database) error {
				close(writerEntered)
				// Same arbitrary passkey-account attributes as a Secret Service
				// Attributes update, without any FIDO service locking.
				entry := gokeepasslib.NewEntry()
				entry.Values = []gokeepasslib.ValueData{
					{Key: "KPEX_PASSKEY_RPID", Value: gokeepasslib.V{Content: "example.com"}},
					{Key: "KPEX_PASSKEY_HANDLE", Value: gokeepasslib.V{Content: "AA"}},
				}
				db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)
				return nil
			})
		}()
		// Open a different UUID to avoid making the independent writer stale;
		// Lock targets the other database for the same reason.
		newPath := createTestKDBX(GinkgoT().TempDir(), "new.kdbx", "password", nil)
		go func() {
			close(lifecycleStarted)
			if reopen {
				_, err := pool.Open(newPath, PasswordCredential(password))
				lifecycleDone <- err
			} else {
				id := otherID
				if !writeTarget {
					id = uuid
				}
				lifecycleDone <- pool.Lock(id)
			}
		}()
		Eventually(writerStarted, time.Second).Should(BeClosed())
		Eventually(lifecycleStarted, time.Second).Should(BeClosed())
		select {
		case <-writerEntered:
			Fail("writer entered its mutation callback inside check/save gap")
		default:
		}
		select {
		case err := <-writerDone:
			Fail(fmt.Sprintf("writer completed inside check/save gap: %v", err))
		default:
		}
		select {
		case err := <-lifecycleDone:
			Fail(fmt.Sprintf("lifecycle completed inside check/save gap: %v", err))
		default:
		}
		unblock()
		Eventually(atomicDone, 5*time.Second).Should(Receive(Succeed()))
		Eventually(writerDone, 5*time.Second).Should(Receive(Succeed()))
		Eventually(lifecycleDone, 5*time.Second).Should(Receive(Succeed()))
	}, Entry("target writer and lock", true, false), Entry("other writer and lock", false, false), Entry("target writer and open", true, true), Entry("other writer and open", false, true))

	DescribeTable("refuses an unlocked instance displaced directly by Open", func(copied bool) {
		pool, uuid, selected := openTestKDBX("selected.kdbx", "password", nil, nil)
		// Open currently replaces same-UUID membership without closing the old
		// watcher. Own that displaced fixture resource explicitly in this spec.
		DeferCleanup(func() {
			selected.Watcher.cancel()
			<-selected.Watcher.done
		})
		before, err := os.ReadFile(selected.Path)
		Expect(err).NotTo(HaveOccurred())
		path := selected.Path
		if copied {
			path = GinkgoT().TempDir() + "/copy.kdbx"
			Expect(os.WriteFile(path, before, 0600)).To(Succeed())
		}
		password, err := security.NewSecureString("password")
		Expect(err).NotTo(HaveOccurred())
		defer password.Destroy()
		newID, err := pool.Open(path, PasswordCredential(password))
		Expect(err).NotTo(HaveOccurred())
		Expect(newID).To(Equal(uuid))
		Expect(selected.Locked).To(BeFalse())
		called := false
		err = pool.UpdateAndSaveWithUnlockedDatabases(selected, func(map[*OpenDatabase]*gokeepasslib.Database) error {
			called = true
			return nil
		})
		Expect(err).To(MatchError(ContainSubstring("unavailable")))
		Expect(called).To(BeFalse())
		for _, file := range []string{path, selected.Path} {
			after, err := os.ReadFile(file)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before))
		}
	}, Entry("copied path", true), Entry("same path", false))

	It("restores the entire group, entry and history identity tree after a pre-rename save failure", func() {
		_, _, target := openTestKDBX("rollback.kdbx", "password", nil, nil)
		Expect(target.UpdateAndSave(func(db *gokeepasslib.Database) error {
			nested := gokeepasslib.NewGroup()
			leaf := gokeepasslib.NewGroup()
			entry := gokeepasslib.NewEntry()
			history := gokeepasslib.NewEntry()
			history.Histories = []gokeepasslib.History{{Entries: []gokeepasslib.Entry{gokeepasslib.NewEntry()}}}
			entry.Histories = []gokeepasslib.History{{Entries: []gokeepasslib.Entry{history}}}
			leaf.Entries = []gokeepasslib.Entry{entry, gokeepasslib.NewEntry()}
			nested.Groups = []gokeepasslib.Group{leaf}
			db.Content.Root.Groups[0].Groups = []gokeepasslib.Group{nested}
			db.Content.Root.Groups[0].Entries = []gokeepasslib.Entry{gokeepasslib.NewEntry()}
			return nil
		})).To(Succeed())
		before, err := os.ReadFile(target.Path)
		Expect(err).NotTo(HaveOccurred())
		original, err := xml.Marshal(target.Db.Content.Root)
		Expect(err).NotTo(HaveOccurred())
		file, err := os.Open(target.Path)
		Expect(err).NotTo(HaveOccurred())
		defer file.Close()
		target.Path = fmt.Sprintf("/proc/self/fd/%d", file.Fd())
		err = target.UpdateAndSave(func(db *gokeepasslib.Database) error {
			db.Content.Root.Groups[0].Name = "mutated"
			db.Content.Root.Groups[0].Groups[0].Groups[0].Entries = nil
			return nil
		})
		Expect(err).To(HaveOccurred())
		restored, err := xml.Marshal(target.Db.Content.Root)
		Expect(err).NotTo(HaveOccurred())
		Expect(restored).To(Equal(original))
		after, err := os.ReadFile(target.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	})
})
