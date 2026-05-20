//go:build linux

// Package xdg centralizes kpxcd's XDG base-directory paths and secure
// filesystem helpers.
package xdg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfigHome returns $XDG_CONFIG_HOME or ~/.config.
func ConfigHome() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".config"
	}
	return filepath.Join(home, ".config")
}

// DataHome returns $XDG_DATA_HOME or ~/.local/share.
func DataHome() string {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".local", "share")
	}
	return filepath.Join(home, ".local", "share")
}

// RuntimeDir returns $XDG_RUNTIME_DIR. Unlike ConfigHome/DataHome, there is no
// secure fallback suitable for PAM handoff tokens.
func RuntimeDir() (string, error) {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("XDG_RUNTIME_DIR is not set")
}

func ConfigDir() string { return filepath.Join(ConfigHome(), "kpxcd") }
func DataDir() string   { return filepath.Join(DataHome(), "kpxcd") }

func RuntimeKpxcdDir() (string, error) {
	run, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(run, "kpxcd"), nil
}

func ConfigPath() string            { return filepath.Join(ConfigDir(), "config.toml") }
func DefaultDatabasePath() string   { return filepath.Join(DataDir(), "default.kdbx") }
func DefaultIdentityPath() string   { return filepath.Join(DataDir(), "default.identity.age") }
func DefaultCredentialPath() string { return filepath.Join(DataDir(), "default.cred.age") }

func PAMTokenPath() (string, error) {
	dir, err := RuntimeKpxcdDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pam-token"), nil
}

// EnsurePrivateDir creates a directory tree with private user-only
// permissions. Existing directories are chmod'd best-effort to the requested
// mode to avoid accidentally world-readable kpxcd state.
func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

// WritePrivateFile writes a secret-bearing file with mode 0600. The parent
// directory is created with mode 0700.
func WritePrivateFile(path string, data []byte) error {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// ExpandPath expands ~ and XDG environment variables with kpxcd's fallback
// values. Relative paths are resolved against $XDG_CONFIG_HOME/kpxcd to retain
// historical config behavior.
func ExpandPath(path string) string {
	if path == "" {
		return path
	}
	expanded := os.Expand(path, func(key string) string {
		switch key {
		case "HOME":
			home, _ := os.UserHomeDir()
			return home
		case "XDG_CONFIG_HOME":
			return ConfigHome()
		case "XDG_DATA_HOME":
			return DataHome()
		case "XDG_RUNTIME_DIR":
			run, _ := RuntimeDir()
			return run
		default:
			return os.Getenv(key)
		}
	})
	if strings.HasPrefix(expanded, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			expanded = filepath.Join(home, expanded[2:])
		}
	} else if expanded == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			expanded = home
		}
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(ConfigDir(), expanded)
	}
	return filepath.Clean(expanded)
}
