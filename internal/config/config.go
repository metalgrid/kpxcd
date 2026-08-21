//go:build linux

// Package config handles TOML configuration parsing for kpxcd.
// It supports XDG directory resolution, ~ and $HOME expansion in paths,
// and provides helpful error messages for common configuration mistakes.
package config

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/metalgrid/kpxcd/internal/xdg"
)

//go:embed defaults/config.toml
var defaultConfigFS embed.FS

// DaemonConfig holds the top-level daemon settings.
type DaemonConfig struct {
	IdleTimeout      int    `toml:"idle_timeout"`
	LockOnScreenlock bool   `toml:"lock_on_screenlock"`
	LogLevel         string `toml:"log_level"`
	LogToJournald    bool   `toml:"log_to_journald"`
	SSHSocketPath    string `toml:"ssh_socket_path"`
	SSHMode          string `toml:"ssh_mode"`
}

// DatabaseConfig describes a single KeePass database.
type DatabaseConfig struct {
	Path                     string `toml:"path"`
	Name                     string `toml:"name"`
	Default                  bool   `toml:"default"`
	AutoUnlock               bool   `toml:"auto_unlock"`
	UnlockCredential         string `toml:"unlock_credential"`
	SystemdCredentialName    string `toml:"systemd_credential_name"`
	Keyfile                  string `toml:"keyfile"`
	YubikeySlot              int    `toml:"yubikey_slot"`
	SecretServiceExposeGroup string `toml:"secret_service_expose_group"`
	SSHAutoAdd               bool   `toml:"ssh_auto_add"`
}

// SecretServiceConfig holds settings for the Secret Service interface.
type SecretServiceConfig struct {
	Enabled             bool `toml:"enabled"`
	NotifyOnAccess      bool `toml:"notify_on_access"`
	NotifyCacheTTL      int  `toml:"notify_cache_ttl"`
	RequireConfirmation bool `toml:"require_confirmation"`
	ConfirmationTimeout int  `toml:"confirmation_timeout"`
}

// SSHAgentConfig holds settings for the SSH agent interface.
type SSHAgentConfig struct {
	Enabled             bool   `toml:"enabled"`
	RemoveOnLock        bool   `toml:"remove_on_lock"`
	ConfirmOnUse        bool   `toml:"confirm_on_use"`
	Lifetime            int    `toml:"lifetime"`
	SecurityKeyProvider string `toml:"security_key_provider"`
}

// Fido2Config holds settings for the FIDO2 / passkey interface.
type Fido2Config struct {
	Enabled          bool   `toml:"enabled"`
	AAGUID           string `toml:"aaguid"`
	Algorithms       []int  `toml:"algorithms"`
	UserVerification string `toml:"user_verification"`
}

// Config is the top-level configuration structure.
type Config struct {
	Daemon        DaemonConfig        `toml:"daemon"`
	Databases     []DatabaseConfig    `toml:"database"`
	SecretService SecretServiceConfig `toml:"secret_service"`
	SSHAgent      SSHAgentConfig      `toml:"ssh_agent"`
	Fido2         Fido2Config         `toml:"fido2"`
}

// Load reads and parses a TOML configuration file from the given path.
// If path is empty, it resolves the default config location using XDG.
//
// Path expansion:
//   - ~ is replaced with the user's home directory
//   - $HOME and other environment variables are expanded
//   - Relative paths are resolved against $XDG_CONFIG_HOME/kpxcd/
//   - Absolute paths are used as-is
func Load(path string) (*Config, error) {
	explicitPath := path != ""
	if path == "" {
		var err error
		path, err = defaultConfigPath()
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !explicitPath {
			if err := createDefaultConfig(path); err != nil {
				return nil, fmt.Errorf("config: create default config: %w", err)
			}
			data, err = os.ReadFile(path)
		}
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("config: file not found: %s", path)
			}
			return nil, fmt.Errorf("config: cannot read %s: %w", path, err)
		}
	}

	cfg := DefaultConfig()
	meta, err := toml.Decode(string(data), cfg)
	if err != nil {
		return nil, fmt.Errorf("config: parse error in %s:\n%w", path, err)
	}

	// Report unknown keys as warnings (not errors) for user feedback.
	// Struct keys are the ones defined in our Config type.
	structKeys := meta.Keys()
	unknownKeys := make(map[string][]string) // section -> keys
	for _, k := range structKeys {
		// toml.Decode preserves all keys; we check for ones that
		// might be typos or deprecated options.
		// This is informational only — we don't fail on unknown keys.
		_ = k
	}
	_ = unknownKeys // silence unused warning for now

	// Post-process: expand paths and derive names.
	for i := range cfg.Databases {
		cfg.Databases[i].Path = expandPath(cfg.Databases[i].Path)
		cfg.Databases[i].Keyfile = expandPath(cfg.Databases[i].Keyfile)
		if cfg.Databases[i].Name == "" {
			cfg.Databases[i].Name = filepath.Base(cfg.Databases[i].Path)
		}
	}

	return cfg, nil
}

// DefaultConfig returns a Config populated with sensible defaults matching
// the specification in doc/config.md.
func DefaultConfig() *Config {
	return &Config{
		Daemon: DaemonConfig{
			IdleTimeout:      0,
			LockOnScreenlock: false,
			LogLevel:         "info",
			LogToJournald:    true,
			SSHSocketPath:    "kpxcd/ssh.sock",
			SSHMode:          "agent",
		},
		SecretService: SecretServiceConfig{
			Enabled:             true,
			NotifyOnAccess:      true,
			NotifyCacheTTL:      300,
			RequireConfirmation: false,
			ConfirmationTimeout: 30,
		},
		SSHAgent: SSHAgentConfig{
			Enabled:             true,
			RemoveOnLock:        true,
			ConfirmOnUse:        false,
			Lifetime:            0,
			SecurityKeyProvider: "internal",
		},
		Fido2: Fido2Config{
			Enabled:          false,
			AAGUID:           "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
			Algorithms:       []int{-7, -8},
			UserVerification: "preferred",
		},
	}
}

// expandPath performs shell-like path expansion:
//   - ~ or ~/ is replaced with the user's home directory
//   - $HOME, $XDG_* and other environment variables are expanded
//   - Relative paths are resolved against $XDG_CONFIG_HOME/kpxcd/
//   - Absolute paths are returned unchanged
//   - Empty strings are returned unchanged
func expandPath(path string) string {
	return xdg.ExpandPath(path)
}

// xdgConfigHome returns the XDG configuration directory, falling back to
// ~/.config if XDG_CONFIG_HOME is not set.
func xdgConfigHome() string {
	return xdg.ConfigHome()
}

// defaultConfigPath resolves the default configuration file location.
// It checks XDG_CONFIG_HOME first, then falls back to ~/.config.
func defaultConfigPath() (string, error) {
	return xdg.ConfigPath(), nil
}

func createDefaultConfig(path string) error {
	data, err := defaultConfigFS.ReadFile("defaults/config.toml")
	if err != nil {
		return err
	}
	return xdg.WritePrivateFile(path, data)
}

// Validate checks that the configuration is internally consistent
// and provides helpful error messages for common mistakes.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Daemon.LogLevel) == "" {
		c.Daemon.LogLevel = "info"
	}

	// Validate ssh_mode.
	switch c.Daemon.SSHMode {
	case "", "agent", "proxy", "client":
		if c.Daemon.SSHMode == "" {
			c.Daemon.SSHMode = "agent"
		}
	default:
		return fmt.Errorf("config: invalid ssh_mode %q, must be \"agent\", \"proxy\", or \"client\"", c.Daemon.SSHMode)
	}

	// Validate databases.
	defaultCount := 0
	for i, db := range c.Databases {
		if db.Default {
			defaultCount++
		}
		if db.Path == "" {
			return fmt.Errorf("config: database[%d]: path is required", i)
		}

		switch db.UnlockCredential {
		case "", "prompt", "systemd-credential", "keyfile", "pam", "none":
			if db.UnlockCredential == "" {
				c.Databases[i].UnlockCredential = "prompt"
			}
		default:
			return fmt.Errorf("config: database[%d] (%s): invalid unlock_credential %q, "+
				"must be one of: systemd-credential, keyfile, pam, prompt, none",
				i, db.Name, db.UnlockCredential)
		}

		// Warn about suspicious path configurations.
		if db.UnlockCredential == "none" && db.Keyfile == "" {
			// User explicitly chose no password with no keyfile — this is insecure.
			// We allow it but could log a warning.
		}

		// Validate systemd credential name when required.
		if db.UnlockCredential == "systemd-credential" && db.SystemdCredentialName == "" {
			return fmt.Errorf("config: database[%d] (%s): systemd_credential_name is required "+
				"when unlock_credential = \"systemd-credential\"", i, db.Name)
		}

		// Validate keyfile path when required.
		if db.UnlockCredential == "keyfile" && db.Keyfile == "" {
			return fmt.Errorf("config: database[%d] (%s): keyfile is required "+
				"when unlock_credential = \"keyfile\"", i, db.Name)
		}
	}

	if defaultCount > 1 {
		return fmt.Errorf("config: at most one database may be marked default")
	}

	return nil
}
