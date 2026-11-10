//go:build linux

package sshagent

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/config"
)

var _ = Describe("GenerateTestKey", func() {
	DescribeTable("generates a usable key for every supported type",
		func(kt string) {
			key, err := GenerateTestKey(kt)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
			Expect(key.Signer).NotTo(BeNil())
			Expect(key.Blob).NotTo(BeEmpty())
			Expect(key.Format).NotTo(BeEmpty())
			Expect(key.Comment).To(Equal("test@" + kt))
		},
		Entry("rsa", "rsa"),
		Entry("ed25519", "ed25519"),
		Entry("ecdsa-p256", "ecdsa-p256"),
	)

	It("refuses an unsupported key type", func() {
		_, err := GenerateTestKey("unsupported")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("Key.Fingerprint", func() {
	It("returns a stable SHA256 fingerprint unique per key", func() {
		key, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())

		fp := key.Fingerprint()
		Expect(fp).To(HavePrefix("SHA256:"))
		Expect(key.Fingerprint()).To(Equal(fp))

		key2, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())
		Expect(key2.Fingerprint()).NotTo(Equal(fp), "different keys should have different fingerprints")
	})

	It("handles an empty blob", func() {
		Expect((&Key{Blob: nil}).Fingerprint()).To(Equal("SHA256:(empty)"))
		Expect((&Key{Blob: []byte{}}).Fingerprint()).To(Equal("SHA256:(empty)"))
	})
})

var _ = Describe("Key.Equal", func() {
	It("compares keys by blob", func() {
		key, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())

		Expect(key.Equal(key)).To(BeTrue())

		key2 := &Key{
			Blob:    make([]byte, len(key.Blob)),
			Comment: key.Comment,
		}
		copy(key2.Blob, key.Blob)
		Expect(key.Equal(key2)).To(BeTrue(), "keys with same blob should be equal")

		key3, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())
		Expect(key.Equal(key3)).To(BeFalse(), "different keys should not be equal")

		var nilKey *Key
		Expect(nilKey.Equal(nilKey)).To(BeTrue(), "nil should equal nil")
		Expect(key.Equal(nil)).To(BeFalse(), "non-nil key should not equal nil")
		Expect(nilKey.Equal(key)).To(BeFalse(), "nil key should not equal non-nil key")
	})
})

var _ = Describe("GenerateTestKey ed25519 signing", func() {
	It("produces a key whose signature verifies against its public key", func() {
		key, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())
		Expect(key.Format).To(Equal("ssh-ed25519"))
		Expect(key.Signer).NotTo(BeNil())

		sshPub := key.Signer.PublicKey()
		Expect(sshPub).NotTo(BeNil())
		Expect(sshPub.Type()).To(Equal("ssh-ed25519"))

		data := []byte("test signing data")
		sig, err := key.Sign(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(sig.Blob).NotTo(BeEmpty())
		Expect(sshPub.Verify(data, sig)).To(Succeed())
	})

	It("refuses invalid key data", func() {
		_, err := ParsePrivateKey([]byte("not a valid key"), "")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("IdentityManager", func() {
	newManager := func() *IdentityManager {
		return NewIdentityManager(&config.SSHAgentConfig{})
	}

	It("adds, lists, finds, and removes identities", func() {
		im := newManager()
		Expect(im).NotTo(BeNil())
		Expect(im.Count()).To(Equal(0))

		key1, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())
		Expect(im.AddIdentity(key1, 0, false, false, "db-uuid-1", "entry-uuid-1")).To(Succeed())
		Expect(im.Count()).To(Equal(1))

		listed := im.ListIdentities()
		Expect(listed).To(HaveLen(1))
		Expect(listed[0].Key.Fingerprint()).To(Equal(key1.Fingerprint()))

		fp := key1.Fingerprint()
		found := im.FindIdentityByFingerprint(fp)
		Expect(found).NotTo(BeNil())
		Expect(found.DBUUID).To(Equal("db-uuid-1"))
		Expect(found.EntryUUID).To(Equal("entry-uuid-1"))

		Expect(im.RemoveIdentity(fp)).To(Succeed())
		Expect(im.Count()).To(Equal(0))
		Expect(im.FindIdentityByFingerprint(fp)).To(BeNil(), "FindIdentityByFingerprint should return nil after removal")
	})

	It("refuses to remove a nonexistent key", func() {
		im := newManager()
		Expect(im.RemoveIdentity("nonexistent-fingerprint")).To(HaveOccurred())
	})

	It("holds and finds multiple keys of different types", func() {
		im := newManager()
		keyTypes := []string{"rsa", "ed25519", "ecdsa-p256"}

		for i, kt := range keyTypes {
			key, err := GenerateTestKey(kt)
			Expect(err).NotTo(HaveOccurred())
			Expect(im.AddIdentity(key, uint32(i*60), false, true, "db-uuid", "entry-uuid")).To(Succeed())
		}
		Expect(im.Count()).To(Equal(3))

		for _, lk := range im.ListIdentities() {
			Expect(im.FindIdentityByFingerprint(lk.Key.Fingerprint())).NotTo(BeNil())
		}
	})

	It("clears every key on RemoveAllIdentities", func() {
		im := newManager()
		key1, _ := GenerateTestKey("rsa")
		key2, _ := GenerateTestKey("ed25519")
		_ = im.AddIdentity(key1, 0, false, false, "db1", "entry1")
		_ = im.AddIdentity(key2, 0, false, false, "db2", "entry2")
		Expect(im.Count()).To(Equal(2))

		im.RemoveAllIdentities()
		Expect(im.Count()).To(Equal(0))
	})

	It("replaces an existing identity with the same fingerprint", func() {
		im := newManager()
		key, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())

		_ = im.AddIdentity(key, 0, false, false, "db-old", "entry-old")
		_ = im.AddIdentity(key, 300, true, true, "db-new", "entry-new")

		Expect(im.Count()).To(Equal(1), "replacement must not duplicate")
		found := im.FindIdentityByFingerprint(key.Fingerprint())
		Expect(found).NotTo(BeNil())
		Expect(found.Lifetime).To(Equal(uint32(300)))
		Expect(found.Confirm).To(BeTrue())
		Expect(found.DBUUID).To(Equal("db-new"))
	})

	Context("with RemoveOnLock", func() {
		It("removes only auto-remove identities for a database", func() {
			im := NewIdentityManager(&config.SSHAgentConfig{RemoveOnLock: true})
			key1, _ := GenerateTestKey("ed25519")
			key2, _ := GenerateTestKey("rsa")

			// Add key1 with autoRemove=true for db1, key2 with autoRemove=false.
			_ = im.AddIdentity(key1, 0, false, true, "db1", "e1")
			_ = im.AddIdentity(key2, 0, false, false, "db1", "e2")
			Expect(im.Count()).To(Equal(2))

			im.RemoveIdentitiesForDatabase("db1")
			Expect(im.Count()).To(Equal(1))
			Expect(im.FindIdentityByFingerprint(key2.Fingerprint())).NotTo(BeNil(),
				"key2 (autoRemove=false) should still exist")
		})
	})

	It("stores lifetime, confirm, auto-remove, and UUID fields on the loaded key", func() {
		im := newManager()
		key, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())

		Expect(im.AddIdentity(key, 120, true, true, "test-db", "test-entry")).To(Succeed())
		found := im.FindIdentityByFingerprint(key.Fingerprint())
		Expect(found).NotTo(BeNil())
		Expect(found.Lifetime).To(Equal(uint32(120)))
		Expect(found.Confirm).To(BeTrue())
		Expect(found.AutoRemove).To(BeTrue())
		Expect(found.DBUUID).To(Equal("test-db"))
		Expect(found.EntryUUID).To(Equal("test-entry"))
		Expect(found.Key.Blob).To(Equal(key.Blob))
	})
})

var _ = Describe("Key setters", func() {
	It("sets entry UUID, DB UUID, and comment", func() {
		key, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())

		key.SetEntryUUID("entry-uuid-123")
		Expect(key.EntryUUID()).To(Equal("entry-uuid-123"))

		key.SetDBUUID("db-uuid-456")
		Expect(key.DBUUID()).To(Equal("db-uuid-456"))

		key.SetComment("new-comment")
		Expect(key.Comment).To(Equal("new-comment"))
	})
})

var _ = Describe("Key.PublicKey", func() {
	It("returns the ssh public key", func() {
		key, err := GenerateTestKey("ed25519")
		Expect(err).NotTo(HaveOccurred())

		pub := key.PublicKey()
		Expect(pub).NotTo(BeNil())
		Expect(pub.Type()).To(Equal("ssh-ed25519"))
	})
})
