//go:build linux

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/pamcred"
	"github.com/metalgrid/kpxcd/internal/xdg"
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

// sendPAMToken connects to the PAM socket and sends a derived token,
// simulating what the PAM module does during session setup.
func sendPAMToken(t *testing.T, password []byte) {
	t.Helper()
	socketPath, err := xdg.PAMSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	token := pamcred.DerivePAMToken(password)

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to connect to PAM socket: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(token); err != nil {
		t.Fatalf("failed to send token: %v", err)
	}
}

// startTestPAMSocket creates and starts a PAMSocketServer for testing.
// Returns the server and a function to wait for the token to be processed.
func startTestPAMSocket(t *testing.T, app *DaemonApp) *PAMSocketServer {
	t.Helper()
	srv := NewPAMSocketServer(app)
	if err := srv.Listen(); err != nil {
		t.Fatalf("failed to start PAM socket: %v", err)
	}
	return srv
}

func TestPAMSocketBootstrapsDefaultDatabase(t *testing.T) {
	dbPath := setupPAMEnv(t)
	app := newPAMTestApp(t, dbPath)
	defer app.pool.Close()

	srv := startTestPAMSocket(t, app)
	defer srv.Close()

	sendPAMToken(t, []byte("login-password"))

	// Give the socket handler goroutine time to process.
	// The handler reads the token and calls unlockOrBootstrapWithPAM.
	waitForDB(t, app, 1)

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
	// Verify no plaintext token file exists.
	if tokenPath, _ := xdg.PAMTokenPath(); fileExists(tokenPath) {
		t.Fatal("plaintext PAM token file should not exist")
	}
}

func TestPAMSocketUnlocksExistingCredential(t *testing.T) {
	dbPath := setupPAMEnv(t)
	app := newPAMTestApp(t, dbPath)
	srv := startTestPAMSocket(t, app)

	sendPAMToken(t, []byte("login-password"))
	waitForDB(t, app, 1)
	srv.Close()
	_ = app.pool.Close()

	// Second login: same password should unlock the existing database.
	app2 := newPAMTestApp(t, dbPath)
	defer app2.pool.Close()
	srv2 := startTestPAMSocket(t, app2)
	defer srv2.Close()

	sendPAMToken(t, []byte("login-password"))
	waitForDB(t, app2, 1)

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

func TestDerivePAMTokenIsDeterministic(t *testing.T) {
	a := pamcred.DerivePAMToken([]byte("password"))
	b := pamcred.DerivePAMToken([]byte("password"))
	if len(a) != pamcred.PAMTokenLen || len(b) != pamcred.PAMTokenLen {
		t.Fatalf("expected %d bytes, got %d and %d", pamcred.PAMTokenLen, len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("HKDF derivation should be deterministic for same password")
		}
	}
}

func TestDerivePAMTokenDiffersFromPassword(t *testing.T) {
	token := pamcred.DerivePAMToken([]byte("password"))
	if string(token) == "password" {
		t.Fatal("derived token must not equal the raw password")
	}
}

func TestDerivePAMTokenDiffersForDifferentPasswords(t *testing.T) {
	a := pamcred.DerivePAMToken([]byte("password1"))
	b := pamcred.DerivePAMToken([]byte("password2"))
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different passwords must produce different tokens")
	}
}

func TestPAMSocketIgnoresWrongLength(t *testing.T) {
	dbPath := setupPAMEnv(t)
	app := newPAMTestApp(t, dbPath)
	defer app.pool.Close()

	srv := startTestPAMSocket(t, app)
	defer srv.Close()

	// Send a token that's too short.
	socketPath, err := xdg.PAMSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("too-short"))

	// Give the handler time to process.
	waitForDB(t, app, 0)

	// Database should NOT be created.
	if fileExists(dbPath) {
		t.Fatal("database should not be created with malformed token")
	}
}

func TestPAMSocketHandlesMultipleConnections(t *testing.T) {
	dbPath := setupPAMEnv(t)
	app := newPAMTestApp(t, dbPath)
	defer app.pool.Close()

	srv := startTestPAMSocket(t, app)
	defer srv.Close()

	// First connection: bootstrap.
	sendPAMToken(t, []byte("login-password"))
	waitForDB(t, app, 1)

	// Second connection with same password: should be ignored (DB already open).
	sendPAMToken(t, []byte("login-password"))

	// Pool should still have exactly 1 database.
	if len(app.pool.List()) != 1 {
		t.Fatalf("expected 1 database, got %d", len(app.pool.List()))
	}
}

// waitForDB polls until the pool has the expected number of databases or
// the test times out.
func waitForDB(t *testing.T, app *DaemonApp, want int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if len(app.pool.List()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if want > 0 && len(app.pool.List()) < want {
		t.Fatalf("timed out waiting for %d databases, got %d", want, len(app.pool.List()))
	}
}
