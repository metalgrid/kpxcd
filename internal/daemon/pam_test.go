//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/kpxcd/internal/config"
	"github.com/user/kpxcd/internal/dbpool"
	"github.com/user/kpxcd/internal/xdg"
)

func newPAMTestApp(t *testing.T, dbPath string) *DaemonApp {
	t.Helper()
	return &DaemonApp{
		cfg: &config.Config{
			Databases: []config.DatabaseConfig{{
				Name:             "Default",
				Path:             dbPath,
				Default:          true,
				AutoUnlock:       true,
				UnlockCredential: "pam",
			}},
		},
		pool: dbpool.NewDatabasePool(nil),
		done: make(chan struct{}),
	}
}

func setupPAMEnv(t *testing.T) (dbPath string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	runtimeDir, err := xdg.RuntimeKpxcdDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := xdg.EnsurePrivateDir(runtimeDir); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(xdg.DataDir(), "default.kdbx")
}

func writePAMToken(t *testing.T, token string) {
	t.Helper()
	path, err := xdg.PAMTokenPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := xdg.WritePrivateFile(path, []byte(token)); err != nil {
		t.Fatal(err)
	}
}

func TestPAMAutoUnlockBootstrapsDefaultDatabase(t *testing.T) {
	dbPath := setupPAMEnv(t)
	writePAMToken(t, "login-password")
	app := newPAMTestApp(t, dbPath)
	defer app.pool.Close()

	app.tryPAMAutoUnlock()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("default DB was not created: %v", err)
	}
	if _, err := os.Stat(xdg.DefaultIdentityPath()); err != nil {
		t.Fatalf("identity was not created: %v", err)
	}
	if _, err := os.Stat(xdg.DefaultCredentialPath()); err != nil {
		t.Fatalf("credential was not created: %v", err)
	}
	if len(app.pool.List()) != 1 {
		t.Fatalf("expected unlocked database in pool, got %d", len(app.pool.List()))
	}
	if tokenPath, _ := xdg.PAMTokenPath(); fileExists(tokenPath) {
		t.Fatal("PAM token was not consumed")
	}
}

func TestPAMAutoUnlockUnlocksExistingCredential(t *testing.T) {
	dbPath := setupPAMEnv(t)
	writePAMToken(t, "login-password")
	app := newPAMTestApp(t, dbPath)
	app.tryPAMAutoUnlock()
	_ = app.pool.Close()

	writePAMToken(t, "login-password")
	app2 := newPAMTestApp(t, dbPath)
	defer app2.pool.Close()
	app2.tryPAMAutoUnlock()
	if len(app2.pool.List()) != 1 {
		t.Fatalf("expected existing credential to unlock DB, got %d databases", len(app2.pool.List()))
	}
}

func TestPAMBootstrapRefusesExistingDBWithoutCredential(t *testing.T) {
	dbPath := setupPAMEnv(t)
	if err := xdg.WritePrivateFile(dbPath, []byte("existing")); err != nil {
		t.Fatal(err)
	}
	app := newPAMTestApp(t, dbPath)
	err := app.unlockOrBootstrapWithPAM(app.cfg.Databases[0], []byte("login-password"))
	if err == nil {
		t.Fatal("expected existing DB without credential to fail")
	}
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatal("existing DB was modified")
	}
}
