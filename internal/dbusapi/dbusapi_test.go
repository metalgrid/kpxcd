//go:build linux

package dbusapi

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/godbus/dbus/v5"
	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
)

// newHandler builds a DaemonDBus over an empty pool, optionally with a
// FIDO2 service. No bus connection is established.
func newHandler(withFido2 bool) *DaemonDBus {
	cfg := config.DefaultConfig()
	pool := dbpool.NewDatabasePool(nil)
	var f2 *fido2.Fido2Service
	if withFido2 {
		f2 = fido2.NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
	}
	return NewDaemonDBus(cfg, pool, f2, nil)
}

var _ = Describe("DaemonDBus.Ping", func() {
	It("answers pong", func() {
		result, err := newHandler(true).Ping()
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal("pong"))
	})

	It("works without a DBus connection", func() {
		result, err := newHandler(false).Ping()
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal("pong"))
	})
})

var _ = Describe("DaemonDBus.ListDatabases", func() {
	It("returns an empty list on an empty pool", func() {
		dbs, err := newHandler(false).ListDatabases("")
		Expect(err).NotTo(HaveOccurred())
		Expect(dbs).NotTo(BeNil())
		Expect(dbs).To(BeEmpty())
	})

	It("returns values typed as []map[string]dbus.Variant", func() {
		dbs, err := newHandler(false).ListDatabases("")
		Expect(err).NotTo(HaveOccurred())
		_, ok := interface{}(dbs).([]map[string]dbus.Variant)
		Expect(ok).To(BeTrue())
	})
})

var _ = Describe("NewDaemonDBus", func() {
	It("wires config, pool, and fido2 service", func() {
		cfg := config.DefaultConfig()
		pool := dbpool.NewDatabasePool(nil)
		f2 := fido2.NewFido2Service(&config.Fido2Config{Enabled: true}, pool)

		handler := NewDaemonDBus(cfg, pool, f2, nil)
		Expect(handler).NotTo(BeNil())
		Expect(handler.config).To(Equal(cfg))
		Expect(handler.pool).To(Equal(pool))
		Expect(handler.fido2).To(Equal(f2))
		Expect(handler.conn).To(BeNil(), "conn should be nil before Export")
	})

	It("accepts a nil fido2 service", func() {
		handler := newHandler(false)
		Expect(handler).NotTo(BeNil())
		Expect(handler.fido2).To(BeNil())
	})
})

var _ = Describe("DaemonDBus.Close", func() {
	It("does not panic without a connection", func() {
		newHandler(false).Close()
	})
})

var _ = Describe("DaemonDBus.LockAll", func() {
	It("succeeds on an empty pool", func() {
		ok, err := newHandler(false).LockAll("")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
	})
})

var _ = Describe("DaemonDBus.LockDatabase", func() {
	It("refuses a nonexistent database", func() {
		ok, err := newHandler(false).LockDatabase("", "nonexistent-uuid")
		Expect(err).To(HaveOccurred())
		Expect(ok).To(BeFalse())
	})
})

var _ = Describe("DaemonDBus.GetEntry", func() {
	It("refuses a nonexistent database", func() {
		_, err := newHandler(false).GetEntry("", "nonexistent-uuid", "some-entry")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("DaemonDBus.authorize", func() {
	It("permits unit-test-style calls with an empty sender and no connection", func() {
		Expect(newHandler(false).authorize("")).To(Succeed())
	})

	It("denies a real sender name with no connection to validate it", func() {
		Expect(newHandler(false).authorize(":1.2")).To(HaveOccurred())
	})
})

var _ = Describe("DaemonDBus.SearchEntries", func() {
	It("returns no results on an empty pool", func() {
		results, err := newHandler(false).SearchEntries("", "", "test")
		Expect(err).NotTo(HaveOccurred())
		Expect(results).To(BeEmpty())
	})

	It("refuses an empty query", func() {
		_, err := newHandler(false).SearchEntries("", "", " ")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("FIDO2 D-Bus methods", func() {
	It("refuse to run when the fido2 service is not running", func() {
		handler := newHandler(false)

		_, err := handler.CreatePasskey("", "db", "example.com", "Example", "user", "User", []int{-7})
		Expect(err).To(MatchError(ContainSubstring("fido2 service is not running")))

		_, err = handler.AssertPasskey("", "example.com", "cred", make([]byte, 32))
		Expect(err).To(MatchError(ContainSubstring("fido2 service is not running")))

		_, err = handler.ListPasskeys("")
		Expect(err).To(MatchError(ContainSubstring("fido2 service is not running")))

		_, err = handler.RemovePasskey("", "cred")
		Expect(err).To(MatchError(ContainSubstring("fido2 service is not running")))

		_, err = handler.ImportPasskey("", "db", "example.com", "Example", "user", "User", "cred", "handle", "PEM", 0)
		Expect(err).To(MatchError(ContainSubstring("fido2 service is not running")))
	})
})
