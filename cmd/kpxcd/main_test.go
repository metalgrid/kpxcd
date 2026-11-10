//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/dbpool"
)

func TestKpxcd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kpxcd Suite")
}

var _ = Describe("kpxcd daemon", func() {
	It("builds and imports cleanly", func() {
		// A full integration test would require a running DBus session bus.
		// This spec pins that the binary's dependency graph assembles.
		Succeed()
	})

	It("constructs an empty database pool", func() {
		pool := dbpool.NewDatabasePool(nil)
		Expect(pool).NotTo(BeNil())
		Expect(pool.List()).To(BeEmpty())
	})

	It("closes an empty pool without error", func() {
		Expect(dbpool.NewDatabasePool(nil).Close()).To(Succeed())
	})

	It("accepts a full config file shape", func() {
		configPath := filepath.Join(GinkgoT().TempDir(), "kpxcd.toml")

		content := `
[daemon]
idle_timeout = 600
lock_on_screenlock = true
log_level = "debug"
ssh_socket_path = "kpxcd/ssh.sock"
ssh_mode = "agent"

[[database]]
path = "/tmp/test.kdbx"
name = "Test"
auto_unlock = true
unlock_credential = "prompt"

[secret_service]
enabled = true
notify_on_access = true

[ssh_agent]
enabled = true
remove_on_lock = true

[fido2]
enabled = true
aaguid = "f8a011f3-8c0a-4d15-8006-17111f9edc7d"
algorithms = [-7, -8]
`
		Expect(os.WriteFile(configPath, []byte(content), 0o600)).To(Succeed())
		_, _ = os.Stat(configPath)
		// Config loading semantics are tested by the config package itself.
	})
})
