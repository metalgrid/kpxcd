//go:build linux

package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("expandPath", func() {
	It("expands a leading tilde against the user home directory", func() {
		home, err := os.UserHomeDir()
		if err != nil {
			Skip("cannot determine home directory")
		}
		Expect(expandPath("~/Passwords.kdbx")).To(Equal(filepath.Join(home, "Passwords.kdbx")))
		Expect(expandPath("~")).To(Equal(home))
		Expect(expandPath("~/Documents/vault.kdbx")).To(Equal(filepath.Join(home, "Documents", "vault.kdbx")))
	})

	It("expands $HOME and ${HOME} against the home directory", func() {
		home := os.Getenv("HOME")
		if home == "" {
			Skip("HOME not set")
		}
		Expect(expandPath("$HOME/Passwords.kdbx")).To(ContainSubstring(home))
		Expect(expandPath("${HOME}/Passwords.kdbx")).To(ContainSubstring(home))
	})

	It("expands $XDG_RUNTIME_DIR", func() {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			Skip("XDG_RUNTIME_DIR not set")
		}
		Expect(expandPath("$XDG_RUNTIME_DIR/kpxcd/ssh.sock")).To(ContainSubstring(xdg))
	})

	It("leaves absolute paths untouched", func() {
		Expect(expandPath("/home/user/Passwords.kdbx")).To(Equal("/home/user/Passwords.kdbx"))
	})

	It("resolves relative paths under the XDG config home", func() {
		expected := filepath.Join(xdgConfigHome(), "kpxcd", "ssh.sock")
		Expect(expandPath("ssh.sock")).To(Equal(expected))
	})

	It("keeps an empty path empty", func() {
		Expect(expandPath("")).To(Equal(""))
	})
})

var _ = Describe("DefaultConfig", func() {
	It("enables the standard integrations and disables the unfinished ones", func() {
		cfg := DefaultConfig()
		Expect(cfg.Daemon.SSHMode).To(Equal("agent"))
		Expect(cfg.SecretService.Enabled).To(BeTrue())
		Expect(cfg.SecretService.NotifyCacheTTL).To(Equal(300))
		Expect(cfg.SSHAgent.Enabled).To(BeTrue())
		Expect(cfg.Fido2.Enabled).To(BeFalse())
	})
})

var _ = Describe("Load", func() {
	It("parses a valid config file and expands paths", func() {
		cfgPath := filepath.Join(GinkgoT().TempDir(), "kpxcd.toml")
		content := `
[daemon]
idle_timeout = 600
log_level = "debug"

[[database]]
path = "~/Passwords.kdbx"
name = "Personal"
auto_unlock = true
unlock_credential = "prompt"

[secret_service]
enabled = true

[ssh_agent]
enabled = true

[fido2]
enabled = true
algorithms = [-7]
`
		Expect(os.WriteFile(cfgPath, []byte(content), 0o600)).To(Succeed())

		cfg, err := Load(cfgPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.Daemon.IdleTimeout).To(Equal(600))
		Expect(cfg.Daemon.LogLevel).To(Equal("debug"))
		Expect(cfg.Databases).To(HaveLen(1))

		home, _ := os.UserHomeDir()
		Expect(cfg.Databases[0].Path).To(Equal(filepath.Join(home, "Passwords.kdbx")))
		Expect(cfg.Databases[0].Name).To(Equal("Personal"))
	})

	It("refuses a missing file and names it in the error", func() {
		_, err := Load("/nonexistent/path/kpxcd.toml")
		Expect(err).To(MatchError(ContainSubstring("/nonexistent/path")))
	})

	It("creates the embedded default config on first run", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))

		cfg, err := Load("")
		Expect(err).NotTo(HaveOccurred())

		path := filepath.Join(dir, "config", "kpxcd", "config.toml")
		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

		Expect(cfg.Databases).To(HaveLen(1))
		Expect(cfg.Databases[0].Default).To(BeTrue())
		Expect(cfg.Databases[0].UnlockCredential).To(Equal("pam"))
		Expect(cfg.Databases[0].Path).To(Equal(filepath.Join(dir, "data", "kpxcd", "default.kdbx")))
	})
})

var _ = Describe("Step 6 FIDO2 configuration compatibility", func() {
	var logs bytes.Buffer
	BeforeEach(func() {
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		DeferCleanup(func() { slog.SetDefault(previous) })
		logs.Reset()
	})
	load := func(content string) (*Config, error) {
		path := filepath.Join(GinkgoT().TempDir(), "config.toml")
		Expect(os.WriteFile(path, []byte(content), 0o600)).To(Succeed())
		cfg, err := Load(path)
		after, readErr := os.ReadFile(path)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(after)).To(Equal(content), "loading never rewrites legacy configuration")
		return cfg, err
	}
	It("loads explicit legacy settings with a diagnostic for every ignored field", func() {
		cfg, err := load(`[fido2]
enabled = true
aaguid = "vendor-or-invalid-identity"
algorithms = [-25, -8]
user_verification = "discouraged"
`)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.Validate()).To(Succeed())
		Expect(cfg.Fido2.Enabled).To(BeTrue())
		Expect(cfg.Fido2.AAGUID).To(Equal("vendor-or-invalid-identity"))
		Expect(cfg.Fido2.Algorithms).To(Equal([]int{-25, -8}))
		Expect(cfg.Fido2.UserVerification).To(Equal("discouraged"))
		for _, key := range []string{"aaguid", "algorithms", "user_verification"} {
			Expect(logs.String()).To(ContainSubstring("key=fido2." + key))
		}
		Expect(logs.String()).To(ContainSubstring("deprecated FIDO2 setting is ignored"))
		Expect(logs.String()).NotTo(ContainSubstring("vendor-or-invalid-identity"))
	})
	It("diagnoses explicitly empty legacy settings too", func() {
		_, err := load("[fido2]\naaguid = \"\"\nalgorithms = []\nuser_verification = \"\"\n")
		Expect(err).NotTo(HaveOccurred())
		for _, key := range []string{"aaguid", "algorithms", "user_verification"} {
			Expect(logs.String()).To(ContainSubstring("key=fido2." + key))
		}
	})
	It("keeps new defaults and examples free of retired assignments and diagnostics", func() {
		Expect(DefaultConfig().Fido2).To(Equal(Fido2Config{}))
		for _, path := range []string{"defaults/config.toml", "../../contrib/kpxcd.toml.example"} {
			data, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			cfg, err := load(string(data))
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Validate()).To(Succeed())
			Expect(cfg.Fido2).To(Equal(Fido2Config{}))
		}
		Expect(logs.String()).To(BeEmpty())
	})
	It("loads enabled-only new configuration without legacy defaults or warnings", func() {
		cfg, err := load("[fido2]\nenabled = true\n")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.Fido2).To(Equal(Fido2Config{Enabled: true}))
		Expect(logs.String()).To(BeEmpty())
	})
	It("refuses misspelled FIDO2 keys rather than silently using defaults", func() {
		_, err := load("[fido2]\nuser_verificaton = \"required\"\n")
		Expect(err).To(MatchError(ContainSubstring("unknown FIDO2 key fido2.user_verificaton")))
	})
	It("preserves typed legacy parsing rather than treating malformed values as unknown", func() {
		_, err := load("[fido2]\nalgorithms = \"ES256\"\n")
		Expect(err).To(MatchError(ContainSubstring("parse error")))
	})
})

var _ = Describe("Validate", func() {
	It("refuses an unknown unlock_credential", func() {
		cfgPath := filepath.Join(GinkgoT().TempDir(), "kpxcd.toml")
		content := `
[[database]]
path = "/tmp/test.kdbx"
unlock_credential = "invalid_value"
`
		Expect(os.WriteFile(cfgPath, []byte(content), 0o600)).To(Succeed())

		cfg, err := Load(cfgPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.Validate()).To(MatchError(ContainSubstring("invalid unlock_credential")))
	})

	It("refuses systemd-credential without a credential name", func() {
		cfgPath := filepath.Join(GinkgoT().TempDir(), "kpxcd.toml")
		content := `
[[database]]
path = "/tmp/test.kdbx"
unlock_credential = "systemd-credential"
`
		Expect(os.WriteFile(cfgPath, []byte(content), 0o600)).To(Succeed())

		cfg, err := Load(cfgPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.Validate()).To(MatchError(ContainSubstring("systemd_credential_name is required")))
	})

	It("refuses more than one default database", func() {
		cfg := DefaultConfig()
		cfg.Databases = []DatabaseConfig{
			{Path: "/tmp/a.kdbx", Name: "A", Default: true, UnlockCredential: "prompt"},
			{Path: "/tmp/b.kdbx", Name: "B", Default: true, UnlockCredential: "prompt"},
		}
		Expect(cfg.Validate()).To(MatchError(ContainSubstring("at most one database may be marked default")))
	})

	It("collects every problem into one error instead of stopping at the first", func() {
		cfg := DefaultConfig()
		cfg.Databases = []DatabaseConfig{
			{Path: "", Name: "A", UnlockCredential: "nonsense"},
			{Path: "/tmp/b.kdbx", Name: "B", UnlockCredential: "systemd-credential"},
		}
		err := cfg.Validate()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("path is required"))
		Expect(err.Error()).To(ContainSubstring("invalid unlock_credential"))
		Expect(err.Error()).To(ContainSubstring("systemd_credential_name is required"))
	})
})
