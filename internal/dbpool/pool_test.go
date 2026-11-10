//go:build linux

package dbpool

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/security"
)

// createTestKDBX creates a minimal KDBX database file with a password
// and returns the file path.
func createTestKDBX(dir, filename, password string, entries []gokeepasslib.Entry) string {
	path := filepath.Join(dir, filename)

	// Use NewDatabase which properly initializes all headers.
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	// Replace the root group entries with our test entries.
	groupUUID := gokeepasslib.NewUUID()
	db.Content.Root.Groups[0].UUID = groupUUID
	db.Content.Root.Groups[0].Name = "TestGroup"
	db.Content.Root.Groups[0].Entries = entries

	Expect(db.LockProtectedEntries()).To(Succeed())

	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	Expect(gokeepasslib.NewEncoder(f).Encode(db)).To(Succeed())

	return path
}

// openTestKDBX creates a test database, opens it in a pool, and returns
// pool, UUID, and the opened database. Resources clean up after the spec.
func openTestKDBX(filename, password string, entries []gokeepasslib.Entry, eventCh chan Event) (*DatabasePool, string, *OpenDatabase) {
	dbPath := createTestKDBX(GinkgoT().TempDir(), filename, password, entries)

	ss, err := security.NewSecureString(password)
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(ss.Destroy)

	pool := NewDatabasePool(eventCh)
	DeferCleanup(func() { _ = pool.Close() })

	uuid, err := pool.Open(dbPath, PasswordCredential(ss))
	Expect(err).NotTo(HaveOccurred())
	Expect(uuid).NotTo(BeEmpty())

	odb, err := pool.Get(uuid)
	Expect(err).NotTo(HaveOccurred())
	return pool, uuid, odb
}

var _ = Describe("NewDatabasePool", func() {
	It("creates an empty pool", func() {
		eventCh := make(chan Event, 10)
		pool := NewDatabasePool(eventCh)
		Expect(pool).NotTo(BeNil())
		Expect(pool.List()).To(BeEmpty())
	})

	It("returns an empty list from List", func() {
		dbs := NewDatabasePool(nil).List()
		Expect(dbs).NotTo(BeNil())
		Expect(dbs).To(BeEmpty())
	})

	It("closes cleanly when empty", func() {
		Expect(NewDatabasePool(nil).Close()).To(Succeed())
	})

	It("locks all cleanly when empty", func() {
		Expect(NewDatabasePool(nil).LockAll()).To(Succeed())
	})
})

var _ = Describe("Pool.Get", func() {
	It("refuses a nonexistent UUID with a non-empty error", func() {
		_, err := NewDatabasePool(nil).Get("nonexistent-uuid")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(BeEmpty())
	})
})

var _ = Describe("Pool.Open", func() {
	It("opens a database and reads its entries", func() {
		testEntries := []gokeepasslib.Entry{
			{
				UUID: gokeepasslib.NewUUID(),
				Values: []gokeepasslib.ValueData{
					{Key: "Title", Value: gokeepasslib.V{Content: "Test Entry 1"}},
					{Key: "UserName", Value: gokeepasslib.V{Content: "testuser"}},
					{Key: "Password", Value: gokeepasslib.V{Content: "s3cr3t", Protected: wrappers.BoolWrapper{Bool: true}}},
					{Key: "URL", Value: gokeepasslib.V{Content: "https://example.com"}},
				},
			},
			{
				UUID: gokeepasslib.NewUUID(),
				Values: []gokeepasslib.ValueData{
					{Key: "Title", Value: gokeepasslib.V{Content: "Test Entry 2"}},
					{Key: "UserName", Value: gokeepasslib.V{Content: "admin"}},
					{Key: "Password", Value: gokeepasslib.V{Content: "p4ssw0rd", Protected: wrappers.BoolWrapper{Bool: true}}},
				},
			},
		}
		dbPath := createTestKDBX(GinkgoT().TempDir(), "test.kdbx", "testpassword", testEntries)

		ss, err := security.NewSecureString("testpassword")
		Expect(err).NotTo(HaveOccurred())
		defer ss.Destroy()

		eventCh := make(chan Event, 10)
		pool := NewDatabasePool(eventCh)
		defer pool.Close()

		uuid, err := pool.Open(dbPath, PasswordCredential(ss))
		Expect(err).NotTo(HaveOccurred())
		Expect(uuid).NotTo(BeEmpty())

		Expect(pool.List()).To(HaveLen(1))

		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())
		Expect(odb.UUID).To(Equal(uuid))
		Expect(odb.Locked).To(BeFalse())

		entries := odb.RootEntries()
		Expect(entries).To(HaveLen(2))
		Expect(entries[0].GetTitle()).To(Equal("Test Entry 1"))
		Expect(entries[0].GetContent("UserName")).To(Equal("testuser"))
		Expect(entries[0].GetContent("URL")).To(Equal("https://example.com"))
		Expect(entries[1].GetTitle()).To(Equal("Test Entry 2"))
	})

	It("refuses a wrong password", func() {
		entries := []gokeepasslib.Entry{
			{
				UUID: gokeepasslib.NewUUID(),
				Values: []gokeepasslib.ValueData{
					{Key: "Title", Value: gokeepasslib.V{Content: "Secret"}},
				},
			},
		}
		dbPath := createTestKDBX(GinkgoT().TempDir(), "wrong.kdbx", "correctpassword", entries)

		wrongSS, err := security.NewSecureString("wrongpassword")
		Expect(err).NotTo(HaveOccurred())
		defer wrongSS.Destroy()

		pool := NewDatabasePool(nil)
		defer pool.Close()

		_, err = pool.Open(dbPath, PasswordCredential(wrongSS))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("Pool lock cycle", func() {
	It("transitions to locked, clears entries, and emits events in order", func() {
		entries := []gokeepasslib.Entry{
			{
				UUID: gokeepasslib.NewUUID(),
				Values: []gokeepasslib.ValueData{
					{Key: "Title", Value: gokeepasslib.V{Content: "LockTest"}},
				},
			},
		}
		eventCh := make(chan Event, 10)
		pool, uuid, odb := openTestKDBX("lock.kdbx", "lockpassword", entries, eventCh)

		Expect(odb.Locked).To(BeFalse())
		Expect(odb.RootEntries()).NotTo(BeEmpty())

		Expect(pool.Lock(uuid)).To(Succeed())

		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())
		Expect(odb.Locked).To(BeTrue())
		Expect(odb.RootEntries()).To(BeEmpty())

		// First event is the unlock from Open, then the lock event.
		ev := <-eventCh
		Expect(ev.Type).To(Equal(EventDatabaseUnlocked))

		ev = <-eventCh
		Expect(ev.Type).To(Equal(EventDatabaseLocked))
		Expect(ev.UUID).To(Equal(uuid))
	})

	It("wipes decrypted content and drops the reference on Lock", func() {
		entries := []gokeepasslib.Entry{
			{
				UUID: gokeepasslib.NewUUID(),
				Values: []gokeepasslib.ValueData{
					{Key: "Title", Value: gokeepasslib.V{Content: "WipeTest"}},
					{Key: "UserName", Value: gokeepasslib.V{Content: "wipeuser"}},
					{Key: "Password", Value: gokeepasslib.V{Content: "wipe-secret", Protected: wrappers.BoolWrapper{Bool: true}}},
				},
			},
		}
		pool, uuid, odb := openTestKDBX("wipe.kdbx", "wipepassword", entries, nil)

		// Capture pointers to the decrypted content before locking.
		contentBefore := odb.Db.Content
		Expect(odb.Db.Content.Root.Groups[0].Entries[0].GetPassword()).To(Equal("wipe-secret"))

		Expect(pool.Lock(uuid)).To(Succeed())

		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())
		Expect(odb.Locked).To(BeTrue())
		Expect(odb.Db).To(BeNil(), "odb.Db should be nil after lock")

		// The captured content should have been wiped.
		Expect(contentBefore.Root.Groups[0].Entries[0].GetPassword()).To(Equal(""), "password was not wiped during lock")
		Expect(contentBefore.Root.Groups[0].Entries[0].GetContent("UserName")).To(Equal(""), "username was not wiped during lock")
	})

	It("survives concurrent Lock, LockAll, and Get calls", func() {
		entries := []gokeepasslib.Entry{
			{
				UUID: gokeepasslib.NewUUID(),
				Values: []gokeepasslib.ValueData{
					{Key: "Title", Value: gokeepasslib.V{Content: "RaceTest"}},
				},
			},
		}
		pool, uuid, _ := openTestKDBX("race.kdbx", "racepassword", entries, make(chan Event, 100))

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = pool.Lock(uuid)
				_ = pool.LockAll()
				_, _ = pool.Get(uuid)
			}()
		}
		wg.Wait()
	})
})
