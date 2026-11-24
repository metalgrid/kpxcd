//go:build linux

package dbusapi

import (
	"os"
	"reflect"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/godbus/dbus/v5"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
	"github.com/metalgrid/kpxcd/internal/sshagent"
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

var _ = Describe("D-Bus method completeness", func() {
	It("every method kpxcctl calls exists on DaemonDBus", func() {
		cli, err := os.ReadFile("../../cmd/kpxcctl/main.go")
		Expect(err).NotTo(HaveOccurred())
		calls := regexp.MustCompile(`iface\+\"\.([A-Za-z]+)\"`).FindAllStringSubmatch(string(cli), -1)
		Expect(calls).NotTo(BeEmpty())
		typ := reflect.TypeOf((*DaemonDBus)(nil))
		for _, c := range calls {
			_, ok := typ.MethodByName(c[1])
			Expect(ok).To(BeTrue(), "kpxcctl calls .%s but DaemonDBus has no such method", c[1])
		}
	})
})

var _ = Describe("attachSSHKey collision rules", func() {
	newKDB := func() *gokeepasslib.Database { return gokeepasslib.NewDatabase() }
	newEntryWithKey := func(kdb *gokeepasslib.Database, pem []byte) *gokeepasslib.Entry {
		entry := gokeepasslib.NewEntry()
		entry.Values = append(entry.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "k"}})
		kdb.Content.Root.Groups[0].Entries = []gokeepasslib.Entry{entry}
		e := &kdb.Content.Root.Groups[0].Entries[0]
		bin := kdb.AddBinary(pem)
		e.Binaries = append(e.Binaries, bin.CreateReference("ssh-key"))
		return e
	}
	genPEM := func() []byte {
		_, pemBytes, err := sshagent.GenerateSSHKeyPair("ed25519", 0)
		Expect(err).NotTo(HaveOccurred())
		return pemBytes
	}

	It("refuses to overwrite a different existing key", func() {
		kdb := newKDB()
		entry := newEntryWithKey(kdb, genPEM())
		err := attachSSHKey(kdb, entry, genPEM())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("refusing to overwrite"))
	})

	It("refuses to overwrite an unparseable existing key (fail closed)", func() {
		kdb := newKDB()
		entry := newEntryWithKey(kdb, []byte("not a key"))
		err := attachSSHKey(kdb, entry, genPEM())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not parse"))
	})

	It("allows same fingerprint (metadata update only)", func() {
		kdb := newKDB()
		pem := genPEM()
		entry := newEntryWithKey(kdb, pem)
		Expect(attachSSHKey(kdb, entry, pem)).To(Succeed())
		Expect(entry.GetContent(sshagent.MarkerSSHKey)).To(Equal("ssh-key"))
	})

	It("refuses a KeeAgent-denied entry", func() {
		kdb := newKDB()
		entry := newEntryWithKey(kdb, genPEM())
		settings, err := sshagent.MarshalEntrySettings(&sshagent.EntrySettings{AllowUseOfSshKey: false})
		Expect(err).NotTo(HaveOccurred())
		bin := kdb.AddBinary(settings)
		entry.Binaries = append(entry.Binaries, bin.CreateReference(sshagent.KeeAgentSettingsAttachment))
		err = attachSSHKey(kdb, entry, genPEM())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("deny"))
	})
})
