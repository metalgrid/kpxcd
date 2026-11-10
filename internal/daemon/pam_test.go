//go:build linux

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/pamcred"
	"github.com/metalgrid/kpxcd/internal/xdg"
)

func newPAMTestApp(dbPath string) *DaemonApp {
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

func setupPAMEnv() string {
	dir := GinkgoT().TempDir()
	GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	GinkgoT().Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	runtimeDir, err := xdg.RuntimeKpxcdDir()
	Expect(err).NotTo(HaveOccurred())
	Expect(xdg.EnsurePrivateDir(runtimeDir)).To(Succeed())
	return filepath.Join(xdg.DataDir(), "default.kdbx")
}

// sendPAMToken connects to the PAM socket and sends a derived token,
// simulating what the PAM module does during session setup.
func sendPAMToken(password []byte) {
	socketPath, err := xdg.PAMSocketPath()
	Expect(err).NotTo(HaveOccurred())
	token := pamcred.DerivePAMToken(password)

	conn, err := net.Dial("unix", socketPath)
	Expect(err).NotTo(HaveOccurred(), "failed to connect to PAM socket")
	defer conn.Close()

	_, err = conn.Write(token)
	Expect(err).NotTo(HaveOccurred(), "failed to send token")
}

// startTestPAMSocket creates and starts a PAMSocketServer for testing.
func startTestPAMSocket(app *DaemonApp) *PAMSocketServer {
	srv := NewPAMSocketServer(app)
	Expect(srv.Listen()).To(Succeed())
	return srv
}

// waitForDB waits until the pool has at least want databases. PAM bootstrap
// uses age scrypt work factors that can be noticeably slower on shared
// runners, so keep this deadline generous to avoid timing-based flakes.
func waitForDB(app *DaemonApp, want int) {
	Eventually(func() int { return len(app.pool.List()) }).
		WithTimeout(30 * time.Second).WithPolling(20 * time.Millisecond).
		Should(BeNumerically(">=", want))
}

var _ = Describe("PAM socket", func() {
	It("bootstraps the default database on first login", func() {
		dbPath := setupPAMEnv()
		app := newPAMTestApp(dbPath)
		defer app.pool.Close()

		srv := startTestPAMSocket(app)
		defer srv.Close()

		sendPAMToken([]byte("login-password"))
		waitForDB(app, 1)

		Expect(dbPath).To(BeAnExistingFile(), "default DB was not created")
		Expect(xdg.DefaultIdentityPath()).To(BeAnExistingFile(), "identity was not created")
		Expect(xdg.DefaultCredentialPath()).To(BeAnExistingFile(), "credential was not created")
		Expect(app.pool.List()).To(HaveLen(1))

		// No plaintext token file may exist.
		tokenPath, _ := xdg.PAMTokenPath()
		Expect(fileExists(tokenPath)).To(BeFalse(), "plaintext PAM token file should not exist")
	})

	It("unlocks the existing credential on a second login", func() {
		dbPath := setupPAMEnv()
		app := newPAMTestApp(dbPath)
		srv := startTestPAMSocket(app)

		sendPAMToken([]byte("login-password"))
		waitForDB(app, 1)
		srv.Close()
		_ = app.pool.Close()

		// Second login: same password should unlock the existing database.
		app2 := newPAMTestApp(dbPath)
		defer app2.pool.Close()
		srv2 := startTestPAMSocket(app2)
		defer srv2.Close()

		sendPAMToken([]byte("login-password"))
		waitForDB(app2, 1)

		Expect(app2.pool.List()).To(HaveLen(1))
	})

	It("ignores tokens of the wrong length", func() {
		dbPath := setupPAMEnv()
		app := newPAMTestApp(dbPath)
		defer app.pool.Close()

		srv := startTestPAMSocket(app)
		defer srv.Close()

		// Send a token that's too short.
		socketPath, err := xdg.PAMSocketPath()
		Expect(err).NotTo(HaveOccurred())
		conn, err := net.Dial("unix", socketPath)
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()
		_, _ = conn.Write([]byte("too-short"))

		// The database must not appear while the handler settles.
		Consistently(func() bool { return fileExists(dbPath) }).
			WithTimeout(500*time.Millisecond).WithPolling(20*time.Millisecond).
			Should(BeFalse(), "database should not be created with malformed token")
	})

	It("handles multiple connections without duplicating databases", func() {
		dbPath := setupPAMEnv()
		app := newPAMTestApp(dbPath)
		defer app.pool.Close()

		srv := startTestPAMSocket(app)
		defer srv.Close()

		// First connection: bootstrap.
		sendPAMToken([]byte("login-password"))
		waitForDB(app, 1)

		// Second connection with same password: should be ignored (DB already open).
		sendPAMToken([]byte("login-password"))

		Expect(app.pool.List()).To(HaveLen(1))
	})
})

var _ = Describe("unlockOrBootstrapWithPAM", func() {
	It("refuses to bootstrap over an existing database without a credential", func() {
		dbPath := setupPAMEnv()
		Expect(xdg.WritePrivateFile(dbPath, []byte("existing"))).To(Succeed())
		app := newPAMTestApp(dbPath)

		err := app.unlockOrBootstrapWithPAM(app.cfg.Databases[0], []byte("login-password"))
		Expect(err).To(HaveOccurred(), "expected existing DB without credential to fail")

		data, err := os.ReadFile(dbPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(Equal("existing"), "existing DB was modified")
	})
})

var _ = Describe("PAM token derivation", func() {
	It("is deterministic for the same password", func() {
		a := pamcred.DerivePAMToken([]byte("password"))
		b := pamcred.DerivePAMToken([]byte("password"))
		Expect(a).To(HaveLen(pamcred.PAMTokenLen))
		Expect(b).To(Equal(a), "HKDF derivation should be deterministic for same password")
	})

	It("differs from the raw password", func() {
		token := pamcred.DerivePAMToken([]byte("password"))
		Expect(string(token)).NotTo(Equal("password"))
	})

	It("differs between different passwords", func() {
		a := pamcred.DerivePAMToken([]byte("password1"))
		b := pamcred.DerivePAMToken([]byte("password2"))
		Expect(a).NotTo(Equal(b))
	})
})
