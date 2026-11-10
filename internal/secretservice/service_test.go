//go:build linux

package secretservice

import (
	"bytes"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
)

// newTestOpenDatabase creates a minimal *dbpool.OpenDatabase for testing.
func newTestOpenDatabase(name, uuid string, locked bool) *dbpool.OpenDatabase {
	return &dbpool.OpenDatabase{
		Name:   name,
		UUID:   uuid,
		Locked: locked,
	}
}

var _ = Describe("pkcs7Pad", func() {
	roundTrip := func(data []byte, blockSize int) {
		padded := pkcs7Pad(data, blockSize)
		Expect(padded).To(HaveLen(((len(data) / blockSize) + 1) * blockSize))
		unpadded, err := pkcs7Unpad(padded)
		Expect(err).NotTo(HaveOccurred())
		Expect(unpadded).To(Equal(data))
	}

	DescribeTable("pads to a whole block and unpads back to the input",
		roundTrip,
		Entry("exact block size", []byte("1234567890123456"), 16),
		Entry("one byte short", []byte("123456789012345"), 16),
		Entry("empty data", []byte{}, 16),
	)

	It("adds a full padding block to exact-size input", func() {
		padded := pkcs7Pad([]byte("1234567890123456"), 16)
		Expect(padded).To(Equal(append([]byte("1234567890123456"), bytes.Repeat([]byte{0x10}, 16)...)))
	})
})

var _ = Describe("PlainSession", func() {
	It("passes plaintext through untouched in both directions", func() {
		sess := NewPlainSession(nil, "/test/session/plain")
		plaintext := []byte("secret password")

		iv, ciphertext, err := sess.Encrypt(plaintext)
		Expect(err).NotTo(HaveOccurred())
		Expect(iv).To(BeNil())
		Expect(ciphertext).To(Equal(plaintext))

		decrypted, err := sess.Decrypt(iv, ciphertext)
		Expect(err).NotTo(HaveOccurred())
		Expect(decrypted).To(Equal(plaintext))
	})
})

var _ = Describe("EncryptedSession", func() {
	It("encrypts to AES-CBC blocks and decrypts back", func() {
		sess := NewEncryptedSession(nil, "/test/session/enc", []byte("0123456789abcdef"))
		plaintext := []byte("secret password 123")

		iv, ciphertext, err := sess.Encrypt(plaintext)
		Expect(err).NotTo(HaveOccurred())
		Expect(iv).To(HaveLen(16))
		Expect(len(ciphertext)).To(BeNumerically(">", 0))
		Expect(len(ciphertext) % 16).To(Equal(0))
		Expect(ciphertext).NotTo(Equal(plaintext))

		decrypted, err := sess.Decrypt(iv, ciphertext)
		Expect(err).NotTo(HaveOccurred())
		Expect(decrypted).To(Equal(plaintext))
	})

	It("refuses to encrypt after Close", func() {
		sess := NewEncryptedSession(nil, "/test/session/close", []byte("0123456789abcdef"))
		sess.Close()

		_, _, err := sess.Encrypt([]byte("test"))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("DeriveSessionKey", func() {
	It("derives a 16-byte key that is stable per secret and distinct across secrets", func() {
		secret := []byte("shared secret data for testing")
		key := DeriveSessionKey(secret)
		Expect(key).To(HaveLen(16))
		Expect(DeriveSessionKey(secret)).To(Equal(key))
		Expect(DeriveSessionKey([]byte("different secret data"))).NotTo(Equal(key))
	})
})

var _ = Describe("EntryAttributes", func() {
	It("maps standard KeePass fields and withholds notes and custom fields", func() {
		entry := gokeepasslib.Entry{
			UUID: gokeepasslib.UUID{},
			Times: gokeepasslib.TimeData{
				CreationTime:         &wrappers.TimeWrapper{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
				LastModificationTime: &wrappers.TimeWrapper{Time: time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)},
			},
			Values: []gokeepasslib.ValueData{
				{Key: "Title", Value: gokeepasslib.V{Content: "My Bank Account"}},
				{Key: "UserName", Value: gokeepasslib.V{Content: "johndoe"}},
				{Key: "Password", Value: gokeepasslib.V{Content: "s3cret!", Protected: wrappers.BoolWrapper{Bool: true}}},
				{Key: "URL", Value: gokeepasslib.V{Content: "https://bank.example.com"}},
				{Key: "Notes", Value: gokeepasslib.V{Content: "Primary savings account\nPIN: 1234"}},
				{Key: "CustomField", Value: gokeepasslib.V{Content: "custom_value"}},
			},
		}
		odb := newTestOpenDatabase("Personal.kdbx", "test-db-uuid-1234", false)

		attrs := EntryAttributes(odb, entry)

		Expect(attrs[AttrTitle]).To(Equal("My Bank Account"))
		Expect(attrs[AttrUserName]).To(Equal("johndoe"))
		Expect(attrs[AttrURL]).To(Equal("https://bank.example.com"))
		Expect(attrs).NotTo(HaveKey(AttrNotes), "notes must not be exposed as Secret Service attributes")
		Expect(attrs[AttrDBNamePrefix]).To(Equal("Personal.kdbx"))
		Expect(attrs[AttrDBUUIDPrefix]).To(Equal("test-db-uuid-1234"))
		Expect(attrs).NotTo(HaveKey("CustomField"), "custom KeePass fields must not be exposed as Secret Service attributes")
	})
})

var _ = Describe("MatchAttributes", func() {
	entry := gokeepasslib.Entry{
		Values: []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: "GitHub"}},
			{Key: "UserName", Value: gokeepasslib.V{Content: "dev@example.com"}},
			{Key: "URL", Value: gokeepasslib.V{Content: "https://github.com/user/repo"}},
			{Key: "Notes", Value: gokeepasslib.V{Content: "Work repository"}},
			{Key: "CustomAttr", Value: gokeepasslib.V{Content: "custom_val"}},
		},
	}
	odb := newTestOpenDatabase("Work.kdbx", "work-uuid", false)

	DescribeTable("matches a query against the entry",
		func(attributes map[string]string, wantMatch bool) {
			Expect(MatchAttributes(entry, odb, attributes)).To(Equal(wantMatch))
		},
		Entry("by title", map[string]string{AttrTitle: "GitHub"}, true),
		Entry("by username", map[string]string{AttrUserName: "dev@example.com"}, true),
		Entry("legacy lowercase username falls back to UserName", map[string]string{"username": "dev@example.com"}, true),
		Entry("by URL", map[string]string{AttrURL: "https://github.com/user/repo"}, true),
		Entry("legacy lowercase url falls back to URL", map[string]string{"url": "https://github.com/user/repo"}, true),
		Entry("partial URL match", map[string]string{AttrURL: "github.com"}, true),
		Entry("by database name", map[string]string{AttrDBNamePrefix: "Work.kdbx"}, true),
		Entry("by custom attribute", map[string]string{"CustomAttr": "custom_val"}, true),
		Entry("non-matching title", map[string]string{AttrTitle: "GitLab"}, false),
		Entry("non-matching username", map[string]string{AttrUserName: "admin@test.com"}, false),
		Entry("multiple matching attributes", map[string]string{AttrTitle: "GitHub", AttrUserName: "dev@example.com"}, true),
		Entry("one matching one not", map[string]string{AttrTitle: "GitHub", AttrUserName: "nobody@test.com"}, false),
		Entry("empty attributes", map[string]string{}, true),
	)

	It("prefers an exact client attribute over the legacy fallback", func() {
		entry := gokeepasslib.Entry{
			Values: []gokeepasslib.ValueData{
				{Key: "UserName", Value: gokeepasslib.V{Content: "legacy-value"}},
				{Key: "username", Value: gokeepasslib.V{Content: "exact-value"}},
			},
		}
		odb := newTestOpenDatabase("Test.kdbx", "test-uuid", false)

		Expect(MatchAttributes(entry, odb, map[string]string{"username": "exact-value"})).To(BeTrue())
		Expect(MatchAttributes(entry, odb, map[string]string{"username": "legacy-value"})).To(BeFalse(),
			"legacy fallback overrode an existing exact client attribute")
	})
})

var _ = Describe("sanitizeCollectionName", func() {
	DescribeTable("makes names path-safe",
		func(input, expect string) {
			Expect(sanitizeCollectionName(input)).To(Equal(expect))
		},
		Entry("plain name", "Personal", "Personal"),
		Entry("extension", "Work.kdbx", "Work_kdbx"),
		Entry("spaces", "my database", "my_database"),
		Entry("special characters", "special!@#$%", "special_____"),
		Entry("slashes", "path/to/file", "path_to_file"),
		Entry("empty", "", "_"),
		Entry("leading digits", "123start", "_123start"),
	)
})

var _ = Describe("collectEntries", func() {
	It("collects entries from nested groups", func() {
		groups := []gokeepasslib.Group{
			{
				Name: "Root",
				Entries: []gokeepasslib.Entry{
					{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Entry 1"}}}},
					{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Entry 2"}}}},
				},
				Groups: []gokeepasslib.Group{
					{
						Name: "SubGroup",
						Entries: []gokeepasslib.Entry{
							{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Entry 3"}}}},
						},
					},
				},
			},
		}

		entries := collectEntries(groups, gokeepasslib.UUID{})
		Expect(entries).To(HaveLen(3))

		titles := make(map[string]bool)
		for _, e := range entries {
			titles[e.GetTitle()] = true
		}
		for _, expected := range []string{"Entry 1", "Entry 2", "Entry 3"} {
			Expect(titles).To(HaveKey(expected))
		}
	})
})

var _ = Describe("collectEntriesVisible", func() {
	It("returns only entries inside the exposed group", func() {
		groups := []gokeepasslib.Group{
			{
				Name: "Root",
				Entries: []gokeepasslib.Entry{
					{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Hidden"}}}},
				},
				Groups: []gokeepasslib.Group{
					{
						Name: "Browser",
						Entries: []gokeepasslib.Entry{
							{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Visible"}}}},
						},
						Groups: []gokeepasslib.Group{
							{
								Name: "Nested",
								Entries: []gokeepasslib.Entry{
									{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Nested visible"}}}},
								},
							},
						},
					},
				},
			},
		}

		entries := collectEntriesVisible(groups, gokeepasslib.UUID{}, "Browser")
		Expect(entries).To(HaveLen(2))
		for _, entry := range entries {
			Expect(entry.GetTitle()).NotTo(Equal("Hidden"), "entry outside exposed group was returned")
		}
	})
})

var _ = Describe("authorizeSecretAccess", func() {
	It("fails closed without a caller PID", func() {
		svc := NewSecretService(nil)
		svc.UpdateConfig(config.SecretServiceConfig{RequireConfirmation: true})
		db := &dbpool.OpenDatabase{Name: "test"}
		item := &Item{coll: &Collection{db: db}, db: db}

		Expect(svc.authorizeSecretAccess(CallerInfo{}, item)).To(HaveOccurred(),
			"confirmation must fail closed without caller PID")
	})
})

var _ = Describe("entryUUIDString", func() {
	It("returns a non-empty string for an entry UUID", func() {
		uuidBytes := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
		uuid := gokeepasslib.UUID{}
		copy(uuid[:], uuidBytes[:])

		Expect(entryUUIDString(gokeepasslib.Entry{UUID: uuid})).NotTo(BeEmpty())
	})
})

var _ = Describe("Prompt", func() {
	It("closes the Done channel after Prompt", func() {
		p := NewPrompt(nil, "/test/prompt/1")
		Expect(p).NotTo(BeNil())
		Expect(string(p.Path())).To(Equal("/test/prompt/1"))

		p.Prompt()
		Eventually(p.Done()).Should(BeClosed())
	})
})

var _ = Describe("Item", func() {
	It("exposes entry fields through its accessors", func() {
		entry := gokeepasslib.Entry{
			UUID: gokeepasslib.UUID{},
			Times: gokeepasslib.TimeData{
				CreationTime:         &wrappers.TimeWrapper{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
				LastModificationTime: &wrappers.TimeWrapper{Time: time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)},
			},
			Values: []gokeepasslib.ValueData{
				{Key: "Title", Value: gokeepasslib.V{Content: "Test Entry"}},
				{Key: "UserName", Value: gokeepasslib.V{Content: "testuser"}},
				{Key: "Password", Value: gokeepasslib.V{Content: "testpass", Protected: wrappers.BoolWrapper{Bool: true}}},
				{Key: "URL", Value: gokeepasslib.V{Content: "https://example.com"}},
			},
		}
		odb := newTestOpenDatabase("Test.kdbx", "test-uuid", false)
		coll := &Collection{db: odb, svc: &SecretService{}}
		item := newItem(nil, coll, entry)

		Expect(item.Label()).To(Equal("Test Entry"))
		Expect(item.Locked()).To(BeFalse())
		Expect(item.Created()).To(Equal(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix()))
		Expect(item.Modified()).To(Equal(time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC).Unix()))

		attrs := item.Attributes()
		Expect(attrs[AttrTitle]).To(Equal("Test Entry"))
		Expect(attrs[AttrUserName]).To(Equal("testuser"))
		Expect(attrs[AttrURL]).To(Equal("https://example.com"))
		Expect(attrs[AttrDBNamePrefix]).To(Equal("Test.kdbx"))
	})
})
