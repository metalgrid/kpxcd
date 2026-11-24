//go:build linux

package secretservice

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/tobischo/gokeepasslib/v3"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Step 5 Secret Service Items lock boundary", func() {
	It("does not retain a database reader while waiting for the service map", func() {
		path := createWritableTestDB(GinkgoT().TempDir(), "password")
		pool, db := openWritableTestDB(path, "password")
		svc := NewSecretService(pool)
		coll := newCollection(nil, svc, db)
		svc.collections[coll.path] = coll
		entry := gokeepasslib.NewEntry()
		Expect(db.UpdateAndSave(func(database *gokeepasslib.Database) error {
			database.Content.Root.Groups[0].Entries = append(database.Content.Root.Groups[0].Entries, entry)
			return nil
		})).To(Succeed())

		// Blocking the map lookup deterministically parks Items before the
		// helper's database lock, without adding a production timing hook.
		svc.mu.Lock()
		mapLocked, itemsReceived := true, false
		itemsDone := make(chan []dbus.ObjectPath, 1)
		go func() {
			paths, _ := coll.Items()
			itemsDone <- paths
		}()
		writerDone := make(chan error, 1)
		writerStarted := false
		defer func() {
			// Removing the lookup also lets the old recursive-lock version
			// unwind on failure, rather than leaving pool.Close deadlocked.
			if !mapLocked {
				svc.mu.Lock()
			}
			delete(svc.collections, coll.path)
			svc.mu.Unlock()
			if !itemsReceived {
				Eventually(itemsDone, 5*time.Second).Should(Receive())
			}
			if writerStarted {
				Eventually(writerDone, 5*time.Second).Should(Receive())
			}
		}()
		Eventually(func() bool {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			for stack := range strings.SplitSeq(string(buf[:n]), "\n\n") {
				if strings.Contains(stack, ".itemsForCollection(") && strings.Contains(stack, "sync.(*RWMutex).RLock") {
					return true
				}
			}
			return false
		}, 5*time.Second).Should(BeTrue(), "Items must reach the blocked service-map lookup")

		entered := make(chan struct{})
		writerStarted = true
		go func() {
			writerDone <- pool.UpdateAndSaveWithUnlockedDatabases(db, func(databases map[*dbpool.OpenDatabase]*gokeepasslib.Database) error {
				if databases[db] == nil {
					return fmt.Errorf("test target unavailable")
				}
				close(entered)
				return nil
			})
		}()
		Eventually(entered, 5*time.Second).Should(BeClosed(), "the map-blocked enumeration must not retain a database reader")
		// The callback proves the competing writer acquired the target lock;
		// returning it to the buffered channel proves persistence completed.
		var err error
		Eventually(writerDone, 5*time.Second).Should(Receive(&err))
		writerStarted = false
		Expect(err).NotTo(HaveOccurred())
		svc.mu.Unlock()
		mapLocked = false
		var paths []dbus.ObjectPath
		Eventually(itemsDone, 5*time.Second).Should(Receive(&paths))
		itemsReceived = true
		Expect(paths).To(ContainElement(itemPathForEntry(db.Name, entry)))
	})

	DescribeTable("returns no items for unavailable collection content", func(state string) {
		db := &dbpool.OpenDatabase{Name: "isolated", Db: gokeepasslib.NewDatabase()}
		svc := NewSecretService(dbpool.NewDatabasePool(nil))
		coll := newCollection(nil, svc, db)
		svc.collections[coll.path] = coll
		switch state {
		case "missing":
			delete(svc.collections, coll.path)
		case "locked":
			db.Locked = true
		case "database":
			db.Db = nil
		case "content":
			db.Db.Content = nil
		case "root":
			db.Db.Content.Root = nil
		}
		paths, err := coll.Items()
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).To(BeEmpty())
		if state != "root" {
			Expect(paths).To(BeNil())
		}
	}, Entry("missing collection", "missing"), Entry("locked database", "locked"), Entry("missing database", "database"), Entry("missing content", "content"), Entry("missing root", "root"))
})
