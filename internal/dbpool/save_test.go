//go:build linux

package dbpool

import (
	"os"
	"path/filepath"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/security"
)

var _ = Describe("UpdateAndSave", func() {
	It("persists a mutation to disk", func() {
		entries := []gokeepasslib.Entry{{
			UUID: gokeepasslib.NewUUID(),
			Values: []gokeepasslib.ValueData{
				{Key: "Title", Value: gokeepasslib.V{Content: "Saved Entry"}},
				{Key: "Password", Value: gokeepasslib.V{Content: "old", Protected: wrappers.BoolWrapper{Bool: true}}},
			},
		}}
		path := createTestKDBX(GinkgoT().TempDir(), "save.kdbx", "password", entries)

		ss, err := security.NewSecureString("password")
		Expect(err).NotTo(HaveOccurred())
		defer ss.Destroy()

		pool := NewDatabasePool(nil)
		defer pool.Close()
		uuid, err := pool.Open(path, PasswordCredential(ss))
		Expect(err).NotTo(HaveOccurred())
		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())

		Expect(odb.UpdateAndSave(func(db *gokeepasslib.Database) error {
			db.Content.Root.Groups[0].Entries[0].Values[1].Value.Content = "new"
			return nil
		})).To(Succeed())

		pool2 := NewDatabasePool(nil)
		defer pool2.Close()
		ss2, err := security.NewSecureString("password")
		Expect(err).NotTo(HaveOccurred())
		defer ss2.Destroy()
		uuid2, err := pool2.Open(path, PasswordCredential(ss2))
		Expect(err).NotTo(HaveOccurred())
		odb2, err := pool2.Get(uuid2)
		Expect(err).NotTo(HaveOccurred())
		Expect(odb2.RootEntries()[0].GetPassword()).To(Equal("new"))
	})

	It("refuses to save over an externally changed file", func() {
		path := createTestKDBX(GinkgoT().TempDir(), "conflict.kdbx", "password", nil)

		ss, err := security.NewSecureString("password")
		Expect(err).NotTo(HaveOccurred())
		defer ss.Destroy()

		pool := NewDatabasePool(nil)
		defer pool.Close()
		uuid, err := pool.Open(path, PasswordCredential(ss))
		Expect(err).NotTo(HaveOccurred())
		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())

		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		Expect(err).NotTo(HaveOccurred())
		_, err = f.Write([]byte("external"))
		_ = f.Close()
		Expect(err).NotTo(HaveOccurred())

		err = odb.UpdateAndSave(func(db *gokeepasslib.Database) error {
			db.Content.Root.Groups[0].Name = "mutated"
			return nil
		})
		Expect(err).To(HaveOccurred(), "expected conflict error")
	})
})

var _ = Describe("save crypto rotation (S1)", func() {
	It("rotates MasterSeed, EncryptionIV and inner stream key on every save and stays readable", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "rot.kdbx")
		ss, err := security.NewSecureString("pw")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(ss.Destroy)
		Expect(CreateDatabase(path, ss)).To(Succeed())

		pool := NewDatabasePool(nil)
		uuid, err := pool.Open(path, PasswordCredential(ss))
		Expect(err).NotTo(HaveOccurred())
		odb, err := pool.Get(uuid)
		Expect(err).NotTo(HaveOccurred())

		read := func() (seed, iv, inner []byte) {
			odb.RLock()
			defer odb.RUnlock()
			return append([]byte{}, odb.Db.Header.FileHeaders.MasterSeed...),
				append([]byte{}, odb.Db.Header.FileHeaders.EncryptionIV...),
				append([]byte{}, odb.Db.Content.InnerHeader.InnerRandomStreamKey...)
		}
		s1, i1, n1 := read()
		Expect(odb.UpdateAndSave(func(db *gokeepasslib.Database) error {
			db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, gokeepasslib.NewEntry())
			return nil
		})).To(Succeed())
		s2, i2, n2 := read()
		Expect(s1).NotTo(Equal(s2), "MasterSeed must rotate")
		Expect(i1).NotTo(Equal(i2), "EncryptionIV must rotate")
		Expect(n1).NotTo(Equal(n2), "InnerRandomStreamKey must rotate")

		// Reopen from disk: everything still decrypts.
		pool2 := NewDatabasePool(nil)
		ss2, err := security.NewSecureString("pw")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(ss2.Destroy)
		uuid2, err := pool2.Open(path, PasswordCredential(ss2))
		Expect(err).NotTo(HaveOccurred())
		odb2, err := pool2.Get(uuid2)
		Expect(err).NotTo(HaveOccurred())
		Expect(odb2.RootEntries()).To(HaveLen(1))
	})
})
