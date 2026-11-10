//go:build linux

package dbpool

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/security"
)

var _ = Describe("CreateDatabase", func() {
	It("creates a secure KDBX that the pool can open", func() {
		path := filepath.Join(GinkgoT().TempDir(), "kpxcd", "default.kdbx")
		ss, err := security.NewSecureString("password")
		Expect(err).NotTo(HaveOccurred())
		defer ss.Destroy()

		Expect(CreateDatabase(path, ss)).To(Succeed())

		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

		pool := NewDatabasePool(nil)
		defer pool.Close()
		_, err = pool.Open(path, PasswordCredential(ss))
		Expect(err).NotTo(HaveOccurred())
	})

	It("refuses to overwrite an existing file", func() {
		path := filepath.Join(GinkgoT().TempDir(), "default.kdbx")
		Expect(os.WriteFile(path, []byte("existing"), 0o600)).To(Succeed())

		ss, err := security.NewSecureString("password")
		Expect(err).NotTo(HaveOccurred())
		defer ss.Destroy()

		Expect(CreateDatabase(path, ss)).To(HaveOccurred(), "expected existing database error")

		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(Equal("existing"), "existing file was modified")
	})
})
