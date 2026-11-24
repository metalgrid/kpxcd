//go:build linux

package dbusapi

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/godbus/dbus/v5"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
	"github.com/metalgrid/kpxcd/internal/security"
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
		_, pemBytes, err := sshagent.GenerateSSHKeyPair("ed25519", 0, "")
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

var _ = Describe("SshSetAutoload / scan round-trip", func() {
	newVaultWithEntry := func(marker, settingsXML, legacyXML string, withKey bool) (*DaemonDBus, *dbpool.DatabasePool, string, string) {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "v.kdbx")
		kdb := gokeepasslib.NewDatabase()
		kdb.Credentials = gokeepasslib.NewPasswordCredentials("pw")
		entry := gokeepasslib.NewEntry()
		entry.Values = append(entry.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "k"}})
		if marker != "" {
			entry.Values = append(entry.Values, gokeepasslib.ValueData{Key: sshagent.MarkerSSHKey, Value: gokeepasslib.V{Content: marker}})
		}
		if withKey {
			_, pemBytes, err := sshagent.GenerateSSHKeyPair("ed25519", 0, "")
			Expect(err).NotTo(HaveOccurred())
			bin := kdb.AddBinary(pemBytes)
			entry.Binaries = append(entry.Binaries, bin.CreateReference("id_ed25519"))
		}
		if settingsXML != "" {
			bin := kdb.AddBinary([]byte(settingsXML))
			entry.Binaries = append(entry.Binaries, bin.CreateReference(sshagent.KeeAgentSettingsAttachment))
		}
		if legacyXML != "" {
			entry.CustomData = append(entry.CustomData, gokeepasslib.CustomData{Key: sshagent.KeeAgentSettingsAttachment, Value: legacyXML})
		}
		kdb.Content.Root.Groups[0].Entries = []gokeepasslib.Entry{entry}
		Expect(kdb.LockProtectedEntries()).To(Succeed())
		f, err := os.Create(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(gokeepasslib.NewEncoder(f).Encode(kdb)).To(Succeed())
		Expect(f.Close()).To(Succeed())

		pool := dbpool.NewDatabasePool(nil)
		ss, err := security.NewSecureString("pw")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(ss.Destroy)
		uuid, err := pool.Open(path, dbpool.PasswordCredential(ss))
		Expect(err).NotTo(HaveOccurred())
		return NewDaemonDBus(config.DefaultConfig(), pool, nil, nil), pool, uuid, path
	}

	entryUUIDHex := func(pool *dbpool.DatabasePool, uuid string) string {
		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())
		odb.RLock()
		defer odb.RUnlock()
		e := odb.Db.Content.Root.Groups[0].Entries[0]
		return fmt.Sprintf("%x", e.UUID[:])
	}

	It("autoload ON on a bare key works via the scan-reported UUID (N1)", func() {
		d, pool, uuid, _ := newVaultWithEntry("", "", "", true)
		eid := entryUUIDHex(pool, uuid)
		// scan reports the same UUID the lookup accepts
		rows, derr := d.SshScanDatabase("", uuid)
		Expect(derr).To(BeNil())
		Expect(rows).To(HaveLen(1))
		scanUUID := getVariantStringDBus(rows[0]["uuid"])
		Expect(scanUUID).To(Equal(eid))
		ok, serr := d.SshSetAutoload("", uuid, scanUUID, true, false)
		Expect(serr).To(BeNil())
		Expect(ok).To(BeTrue())
		// marker now set, settings written
		odb, _ := pool.Get(uuid)
		odb.RLock()
		e := odb.Db.Content.Root.Groups[0].Entries[0]
		Expect(e.GetContent(sshagent.MarkerSSHKey)).To(Equal("id_ed25519"))
		odb.RUnlock()
	})

	It("denied entry: ON without override fails and changes nothing; with override succeeds", func() {
		d, pool, uuid, _ := newVaultWithEntry("", `<EntrySettings><AllowUseOfSshKey>false</AllowUseOfSshKey></EntrySettings>`, "", true)
		eid := entryUUIDHex(pool, uuid)
		ok, serr := d.SshSetAutoload("", uuid, eid, true, false)
		Expect(serr).To(HaveOccurred())
		Expect(ok).To(BeFalse())
		odb, _ := pool.Get(uuid)
		odb.RLock()
		e := odb.Db.Content.Root.Groups[0].Entries[0]
		Expect(e.GetContent(sshagent.MarkerSSHKey)).To(BeEmpty(), "failed call must not write the marker")
		odb.RUnlock()
		ok, serr = d.SshSetAutoload("", uuid, eid, true, true)
		Expect(serr).To(BeNil())
		Expect(ok).To(BeTrue())
	})

	It("OFF never flips Allow and clears the marker; legacy entry gets real settings", func() {
		d, pool, uuid, _ := newVaultWithEntry("id_ed25519", "", `<KeeAgent><allowUseOfSshKey>true</allowUseOfSshKey><location><selectedType>attachment</selectedType><attachment>id_ed25519</attachment></location></KeeAgent>`, true)
		eid := entryUUIDHex(pool, uuid)
		ok, serr := d.SshSetAutoload("", uuid, eid, false, false)
		Expect(serr).To(BeNil())
		Expect(ok).To(BeTrue())
		odb, _ := pool.Get(uuid)
		odb.RLock()
		e := odb.Db.Content.Root.Groups[0].Entries[0]
		Expect(e.GetContent(sshagent.MarkerSSHKey)).To(BeEmpty())
		Expect(e.CustomData).To(BeEmpty(), "legacy custom data replaced")
		hasSettings := false
		for _, b := range e.Binaries {
			if strings.EqualFold(b.Name, sshagent.KeeAgentSettingsAttachment) {
				hasSettings = true
			}
		}
		Expect(hasSettings).To(BeTrue())
		odb.RUnlock()
	})

	It("unreadable settings: ON without override fails; OFF errors and changes nothing", func() {
		d, pool, uuid, _ := newVaultWithEntry("id_ed25519", "garbage <<<", "", true)
		eid := entryUUIDHex(pool, uuid)
		_, serr := d.SshSetAutoload("", uuid, eid, true, false)
		Expect(serr).To(HaveOccurred())
		_, serr = d.SshSetAutoload("", uuid, eid, false, false)
		Expect(serr).To(HaveOccurred())
		odb, _ := pool.Get(uuid)
		odb.RLock()
		e := odb.Db.Content.Root.Groups[0].Entries[0]
		Expect(e.GetContent(sshagent.MarkerSSHKey)).To(Equal("id_ed25519"), "failed calls must not change the entry")
		odb.RUnlock()
	})
})

func getVariantStringDBus(v dbus.Variant) string {
	s, _ := v.Value().(string)
	return s
}

var _ = Describe("governance matrix (state x operation)", func() {
	const (
		allowXML    = `<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey><AddAtDatabaseOpen>true</AddAtDatabaseOpen><Location><SelectedType>attachment</SelectedType><AttachmentName>id_ed25519</AttachmentName></Location></EntrySettings>`
		denyXML     = `<EntrySettings><AllowUseOfSshKey>false</AllowUseOfSshKey></EntrySettings>`
		fileXML     = `<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey><Location><SelectedType>file</SelectedType><FileName>/tmp/k</FileName></Location></EntrySettings>`
		legacyAllow = `<KeeAgent><allowUseOfSshKey>true</allowUseOfSshKey><addAtDatabaseOpen>true</addAtDatabaseOpen><location><selectedType>attachment</selectedType><attachment>id_ed25519</attachment></location></KeeAgent>`
		legacyDeny  = `<KeeAgent><allowUseOfSshKey>false</allowUseOfSshKey></KeeAgent>`
	)

	build := func(state string) (*DaemonDBus, *dbpool.DatabasePool, string) {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "v.kdbx")
		kdb := gokeepasslib.NewDatabase()
		kdb.Credentials = gokeepasslib.NewPasswordCredentials("pw")
		entry := gokeepasslib.NewEntry()
		entry.Values = append(entry.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "k"}})
		_, pemBytes, err := sshagent.GenerateSSHKeyPair("ed25519", 0, "")
		Expect(err).NotTo(HaveOccurred())
		bin := kdb.AddBinary(pemBytes)
		entry.Binaries = append(entry.Binaries, bin.CreateReference("id_ed25519"))
		switch state {
		case "allow":
			entry.Binaries = append(entry.Binaries, kdb.AddBinary([]byte(allowXML)).CreateReference(sshagent.KeeAgentSettingsAttachment))
		case "deny":
			entry.Binaries = append(entry.Binaries, kdb.AddBinary([]byte(denyXML)).CreateReference(sshagent.KeeAgentSettingsAttachment))
		case "file":
			entry.Binaries = append(entry.Binaries, kdb.AddBinary([]byte(fileXML)).CreateReference(sshagent.KeeAgentSettingsAttachment))
		case "unreadable":
			entry.Binaries = append(entry.Binaries, kdb.AddBinary([]byte("garbage <<<")).CreateReference(sshagent.KeeAgentSettingsAttachment))
		case "legacy-allow":
			entry.CustomData = append(entry.CustomData, gokeepasslib.CustomData{Key: sshagent.KeeAgentSettingsAttachment, Value: legacyAllow})
		case "legacy-deny":
			entry.CustomData = append(entry.CustomData, gokeepasslib.CustomData{Key: sshagent.KeeAgentSettingsAttachment, Value: legacyDeny})
		}
		kdb.Content.Root.Groups[0].Entries = []gokeepasslib.Entry{entry}
		Expect(kdb.LockProtectedEntries()).To(Succeed())
		f, err := os.Create(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(gokeepasslib.NewEncoder(f).Encode(kdb)).To(Succeed())
		Expect(f.Close()).To(Succeed())
		pool := dbpool.NewDatabasePool(nil)
		ss, err := security.NewSecureString("pw")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(ss.Destroy)
		uuid, err := pool.Open(path, dbpool.PasswordCredential(ss))
		Expect(err).NotTo(HaveOccurred())
		return NewDaemonDBus(config.DefaultConfig(), pool, nil, nil), pool, uuid
	}

	snapshot := func(pool *dbpool.DatabasePool, uuid string) (allow, addOpen bool, attach, marker string, nBin int) {
		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())
		odb.RLock()
		defer odb.RUnlock()
		e := odb.Db.Content.Root.Groups[0].Entries[0]
		marker = e.GetContent(sshagent.MarkerSSHKey)
		nBin = len(e.Binaries)
		for _, b := range e.Binaries {
			if strings.EqualFold(b.Name, sshagent.KeeAgentSettingsAttachment) {
				bin := odb.Db.FindBinary(b.Value.ID)
				content, _ := bin.GetContentBytes()
				st, err := sshagent.ParseEntrySettings(content)
				if err == nil {
					allow, addOpen, attach = st.AllowUseOfSshKey, st.AddAtDatabaseOpen, st.Location.AttachmentName
				}
			}
		}
		return
	}

	autoLoads := func(pool *dbpool.DatabasePool, uuid string) bool {
		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())
		odb.RLock()
		defer odb.RUnlock()
		keys, err := sshagent.ExtractAutoLoadKeysFromDatabase(odb.Db)
		Expect(err).NotTo(HaveOccurred())
		return len(keys) > 0
	}

	type want struct {
		err       bool
		autoLoads bool
		allow     bool
		addOpen   bool
		attach    string
		marker    string
	}
	// expected outcomes per state; generate = SshGenerateKey
	cases := []struct {
		state string
		op    string
		want  want
	}{
		// ON
		{"none", "ON", want{false, true, true, true, "id_ed25519", "id_ed25519"}},
		{"allow", "ON", want{false, true, true, true, "id_ed25519", "id_ed25519"}},
		{"deny", "ON", want{true, false, false, true, "", ""}},
		{"deny", "ON+override", want{false, true, true, true, "id_ed25519", "id_ed25519"}},
		{"file", "ON", want{true, false, true, false, "", ""}},
		{"unreadable", "ON", want{true, false, false, false, "", ""}},
		{"unreadable", "ON+override", want{false, true, true, true, "id_ed25519", "id_ed25519"}},
		{"legacy-allow", "ON", want{false, true, true, true, "id_ed25519", "id_ed25519"}},
		{"legacy-deny", "ON", want{true, false, false, false, "", ""}},
		{"legacy-deny", "ON+override", want{false, true, true, true, "id_ed25519", "id_ed25519"}},
		// OFF
		{"none", "OFF", want{false, false, false, false, "", ""}}, // bare entry: OFF only clears the marker, no settings written
		{"allow", "OFF", want{false, false, true, false, "id_ed25519", ""}},
		{"deny", "OFF", want{false, false, false, false, "", ""}},
		{"file", "OFF", want{false, false, true, false, "", ""}},
		{"unreadable", "OFF", want{true, false, false, false, "", ""}},
		{"legacy-allow", "OFF", want{false, false, true, false, "id_ed25519", ""}},
		{"legacy-deny", "OFF", want{false, false, false, false, "", ""}},
		// generate
		{"none", "generate", want{true, false, false, false, "", ""}},          // entry already has a key
		{"allow", "generate", want{true, false, true, true, "id_ed25519", ""}}, // refused, unchanged
		{"deny", "generate", want{true, false, false, true, "", ""}},
		{"file", "generate", want{true, false, true, false, "", ""}},
		{"unreadable", "generate", want{true, false, false, false, "", ""}},
		{"legacy-allow", "generate", want{true, false, true, true, "id_ed25519", ""}}, // refused, unchanged
		{"legacy-deny", "generate", want{true, false, false, false, "", ""}},
	}

	for _, c := range cases {
		c := c
		It(fmt.Sprintf("%s / %s", c.state, c.op), func() {
			d, pool, uuid := build(c.state)
			odb, _ := pool.Get(uuid)
			odb.RLock()
			e := odb.Db.Content.Root.Groups[0].Entries[0]
			eid := fmt.Sprintf("%x", e.UUID[:])
			odb.RUnlock()
			beforeAllow, beforeAddOpen, beforeAttach, beforeMarker, beforeBin := snapshot(pool, uuid)

			var derr *dbus.Error
			switch c.op {
			case "ON":
				_, derr = d.SshSetAutoload("", uuid, eid, true, false)
			case "ON+override":
				_, derr = d.SshSetAutoload("", uuid, eid, true, true)
			case "OFF":
				_, derr = d.SshSetAutoload("", uuid, eid, false, false)
			case "generate":
				_, derr = d.SshGenerateKey("", uuid, "k", "ed25519", 0, "")
			}
			if c.want.err {
				Expect(derr).To(HaveOccurred(), "expected an error")
				a, ao, at, m, nb := snapshot(pool, uuid)
				Expect([2]bool{a, ao}).To(Equal([2]bool{beforeAllow, beforeAddOpen}), "on error Allow/AddAtDatabaseOpen must be unchanged")
				Expect(at).To(Equal(beforeAttach))
				Expect(m).To(Equal(beforeMarker))
				Expect(nb).To(Equal(beforeBin))
			} else {
				Expect(derr).To(BeNil())
				a, ao, at, m, _ := snapshot(pool, uuid)
				Expect(a).To(Equal(c.want.allow), "Allow")
				Expect(ao).To(Equal(c.want.addOpen), "AddAtDatabaseOpen")
				Expect(at).To(Equal(c.want.attach), "AttachmentName")
				Expect(m).To(Equal(c.want.marker), "marker")
				Expect(autoLoads(pool, uuid)).To(Equal(c.want.autoLoads), "auto-load extraction")
			}
		})
	}
})
