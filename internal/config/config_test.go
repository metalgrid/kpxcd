//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandPathTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"~/Passwords.kdbx", filepath.Join(home, "Passwords.kdbx")},
		{"~", home},
		{"~/Documents/vault.kdbx", filepath.Join(home, "Documents", "vault.kdbx")},
	}

	for _, tc := range tests {
		got := expandPath(tc.input)
		if got != tc.expected {
			t.Errorf("expandPath(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestExpandPathEnvVar(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}

	tests := []struct {
		input    string
		contains string // check that result contains this substring
	}{
		{"$HOME/Passwords.kdbx", home},
		{"${HOME}/Passwords.kdbx", home},
	}

	for _, tc := range tests {
		got := expandPath(tc.input)
		if !contains(got, tc.contains) {
			t.Errorf("expandPath(%q) = %q, want it to contain %q", tc.input, got, tc.contains)
		}
	}
}

func TestExpandPathXdg(t *testing.T) {
	// XDG_RUNTIME_DIR should be set on most Linux systems.
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		t.Skip("XDG_RUNTIME_DIR not set")
	}

	got := expandPath("$XDG_RUNTIME_DIR/kpxcd/ssh.sock")
	if !contains(got, xdg) {
		t.Errorf("expandPath($XDG_RUNTIME_DIR/...) = %q, want it to contain %q", got, xdg)
	}
}

func TestExpandPathAbsolute(t *testing.T) {
	got := expandPath("/home/user/Passwords.kdbx")
	if got != "/home/user/Passwords.kdbx" {
		t.Errorf("expandPath(/home/user/...) = %q, want /home/user/Passwords.kdbx", got)
	}
}

func TestExpandPathRelative(t *testing.T) {
	xdg := xdgConfigHome()
	got := expandPath("ssh.sock")
	expected := filepath.Join(xdg, "kpxcd", "ssh.sock")
	if got != expected {
		t.Errorf("expandPath(ssh.sock) = %q, want %q", got, expected)
	}
}

func TestExpandPathEmpty(t *testing.T) {
	got := expandPath("")
	if got != "" {
		t.Errorf("expandPath(\"\") = %q, want \"\"", got)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Daemon.SSHMode != "agent" {
		t.Errorf("default ssh_mode = %q, want \"agent\"", cfg.Daemon.SSHMode)
	}
	if !cfg.SecretService.Enabled {
		t.Error("default secret_service.enabled should be true")
	}
	if !cfg.SSHAgent.Enabled {
		t.Error("default ssh_agent.enabled should be true")
	}
	if !cfg.Fido2.Enabled {
		t.Error("default fido2.enabled should be true")
	}
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kpxcd.toml")

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
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Daemon.IdleTimeout != 600 {
		t.Errorf("idle_timeout = %d, want 600", cfg.Daemon.IdleTimeout)
	}
	if cfg.Daemon.LogLevel != "debug" {
		t.Errorf("log_level = %q, want \"debug\"", cfg.Daemon.LogLevel)
	}
	if len(cfg.Databases) != 1 {
		t.Fatalf("expected 1 database, got %d", len(cfg.Databases))
	}

	// Verify that ~ was expanded to home directory.
	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, "Passwords.kdbx")
	if cfg.Databases[0].Path != expected {
		t.Errorf("database path = %q, want %q", cfg.Databases[0].Path, expected)
	}
	if cfg.Databases[0].Name != "Personal" {
		t.Errorf("database name = %q, want \"Personal\"", cfg.Databases[0].Name)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/kpxcd.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	// Should mention the file path.
	if !contains(err.Error(), "/nonexistent/path") {
		t.Errorf("error should mention file path: %v", err)
	}
}

func TestLoadInvalidCredential(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kpxcd.toml")

	content := `
[[database]]
path = "/tmp/test.kdbx"
unlock_credential = "invalid_value"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load should not fail on invalid credential: %v", err)
	}

	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate should reject invalid unlock_credential")
	}
}

func TestValidateSystemdCredentialWithoutName(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kpxcd.toml")

	content := `
[[database]]
path = "/tmp/test.kdbx"
unlock_credential = "systemd-credential"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate should reject systemd-credential without name")
	}
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}