//go:build linux

// Package daemon provides the main daemon lifecycle: config loading,
// signal handling, systemd readiness, and the database pool event loop.
// It wires together the DBus API, Secret Service, SSH agent, and FIDO2
// components and routes database pool events to them.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/godbus/dbus/v5"

	"github.com/user/kpxcd/internal/config"
	"github.com/user/kpxcd/internal/dbpool"
	"github.com/user/kpxcd/internal/dbusapi"
	"github.com/user/kpxcd/internal/fido2"
	"github.com/user/kpxcd/internal/secretservice"
	"github.com/user/kpxcd/internal/security"
	"github.com/user/kpxcd/internal/sshagent"
)

// DaemonApp represents the running daemon.
type DaemonApp struct {
	cfg       *config.Config
	pool      *dbpool.DatabasePool
	dbusAPI   *dbusapi.DaemonDBus
	secSvc    *secretservice.SecretService
	sshAgent  *sshagent.AgentServer
	sshClient *sshagent.AgentClient
	fido2Svc  *fido2.Fido2Service
	dbusConn  *dbus.Conn
	done      chan struct{}
}

// Run starts the kpxcd daemon. It loads configuration, initializes the
// database pool, starts all services (DBus API, Secret Service, SSH agent,
// FIDO2), registers signal handlers, notifies systemd readiness, and runs
// the main event loop. It blocks until a shutdown signal is received.
func Run(configPath string, cliLevel slog.Level) error {
	app := &DaemonApp{
		done: make(chan struct{}),
	}

	// Load configuration.
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	app.cfg = cfg

	// Set up logging. CLI flags (-v, -q) override config file.
	level := cliLevel
	if level == slog.LevelInfo {
		// CLI didn't specify, use config value.
		var err error
		level, err = parseLogLevel(cfg.Daemon.LogLevel)
		if err != nil {
			return err
		}
	}
	if cfg.Daemon.LogToJournald {
		slog.SetDefault(slog.New(newJournaldHandler(level)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		})))
	}

	slog.Info("kpxcd starting", "config", configPath,
		"databases", len(cfg.Databases),
		"secret_service", cfg.SecretService.Enabled,
		"ssh_agent", cfg.SSHAgent.Enabled,
		"fido2", cfg.Fido2.Enabled)

	// Lock all current and future memory pages to prevent swapping.
	// This ensures that decrypted database content, passwords, and keys
	// are never written to swap partitions.
	if err := security.MlockAll(); err != nil {
		slog.Warn("mlockall unavailable — sensitive data may be swapped to disk",
			"hint", "set LimitMEMLOCK=infinity in systemd unit, or run: ulimit -l unlimited")
	} else {
		slog.Info("memory locked (mlockall)")
	}

	// Create database pool with event channel.
	eventCh := make(chan dbpool.Event, 16)
	app.pool = dbpool.NewDatabasePool(eventCh)
	defer app.pool.Close()

	// Connect to the session bus (shared by DaemonDBus + SecretService).
	if err := app.startDBus(); err != nil {
		slog.Error("DBus setup failed", "error", err)
		// Non-fatal: daemon can still manage databases locally.
	}

	// Start the SSH agent.
	if err := app.startSSHAgent(); err != nil {
		slog.Error("SSH agent setup failed", "error", err)
		// Non-fatal: other services can still run.
	}

	// Create FIDO2 service.
	if cfg.Fido2.Enabled {
		app.fido2Svc = fido2.NewFido2Service(&cfg.Fido2, app.pool)
		slog.Info("FIDO2 service initialized",
			"aaguid", cfg.Fido2.AAGUID,
			"algorithms", cfg.Fido2.Algorithms)
	}

	// Register signal handler.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// Auto-unlock databases configured with auto_unlock=true.
	app.autoUnlock()

	// Notify systemd that we are ready.
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		slog.Warn("systemd notify failed (not running under systemd?)", "error", err)
	}

	slog.Info("daemon ready",
		"dbus", app.dbusConn != nil,
		"ssh_agent", app.sshAgent != nil,
		"ssh_client", app.sshClient != nil,
		"fido2", app.fido2Svc != nil)

	// Main event loop.
	if err := app.eventLoop(sigCh, eventCh); err != nil {
		return err
	}

	// Clean shutdown.
	app.shutdown()

	return nil
}

// startDBus connects to the session bus and exports the DaemonDBus and
// (if enabled) Secret Service interfaces.
func (app *DaemonApp) startDBus() error {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return fmt.Errorf("connect to session bus: %w", err)
	}
	app.dbusConn = conn

	// Export org.keepassxc.Daemon interface.
	app.dbusAPI = dbusapi.NewDaemonDBusWithConn(app.cfg, app.pool, app.fido2Svc, conn)
	if err := app.dbusAPI.Export(); err != nil {
		return fmt.Errorf("export daemon DBus API: %w", err)
	}
	slog.Info("DBus: org.keepassxc.Daemon exported")

	// Export org.freedesktop.secrets if enabled.
	if app.cfg.SecretService.Enabled {
		app.secSvc = secretservice.NewSecretService(app.pool, &app.cfg.SecretService)
		if err := app.secSvc.Export(conn); err != nil {
			slog.Warn("Secret Service not exported (another provider may be running)", "error", err)
			app.secSvc = nil
		} else {
			slog.Info("DBus: org.freedesktop.secrets exported")
		}
	}

	return nil
}

// startSSHAgent creates and starts the SSH agent listener or client,
// depending on the configured ssh_mode.
func (app *DaemonApp) startSSHAgent() error {
	if !app.cfg.SSHAgent.Enabled {
		return nil
	}

	switch app.cfg.Daemon.SSHMode {
	case "client", "proxy":
		// In both documented "proxy" mode and legacy "client" mode, kpxcd
		// pushes KeePass keys into the already-registered SSH_AUTH_SOCK agent
		// instead of exposing its own socket.
		return app.startSSHAgentClient()
	default:
		return app.startSSHAgentServer()
	}
}

// startSSHAgentServer starts kpxcd's own SSH agent server (agent mode).
func (app *DaemonApp) startSSHAgentServer() error {
	// Resolve socket path: expand $XDG_RUNTIME_DIR.
	socketPath := os.ExpandEnv(app.cfg.Daemon.SSHSocketPath)
	if !filepath.IsAbs(socketPath) {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			xdg = fmt.Sprintf("/run/user/%d", os.Getuid())
		}
		socketPath = filepath.Join(xdg, socketPath)
	}

	app.sshAgent = sshagent.NewAgentServer(&app.cfg.SSHAgent, app.pool, socketPath)

	if err := app.sshAgent.Listen(); err != nil {
		return fmt.Errorf("SSH agent listen: %w", err)
	}

	// Serve connections in the background.
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := app.sshAgent.Serve(ctx); err != nil {
			slog.Error("SSH agent serve error", "error", err)
		}
	}()

	slog.Info("SSH agent server started", "socket", socketPath)
	return nil
}

// startSSHAgentClient connects to the existing ssh-agent (client mode).
func (app *DaemonApp) startSSHAgentClient() error {
	client, err := sshagent.NewAgentClient(&app.cfg.SSHAgent)
	if err != nil {
		return fmt.Errorf("SSH agent client: %w", err)
	}
	app.sshClient = client
	slog.Info("SSH agent client connected", "socket", os.Getenv("SSH_AUTH_SOCK"))
	return nil
}

// shutdown performs a clean shutdown of all services.
func (app *DaemonApp) shutdown() {
	slog.Info("shutting down")

	// Stop SSH agent.
	if app.sshAgent != nil {
		if err := app.sshAgent.Close(); err != nil {
			slog.Error("SSH agent close error", "error", err)
		}
	}
	if app.sshClient != nil {
		app.sshClient.Close()
	}

	// Release DBus names and close connection.
	if app.dbusAPI != nil {
		app.dbusAPI.Close()
	}
	if app.dbusConn != nil {
		// Secret Service name is released when the connection closes.
		app.dbusConn.Close()
	}

	// Notify systemd that we are stopping.
	_, _ = daemon.SdNotify(false, daemon.SdNotifyStopping)

	// Unlock all memory pages before exit.
	if err := security.MunlockAll(); err != nil {
		slog.Warn("munlockall failed", "error", err)
	}

	slog.Info("daemon stopped")
}

// eventLoop runs the main select loop handling signals and database events.
func (app *DaemonApp) eventLoop(sigCh <-chan os.Signal, eventCh <-chan dbpool.Event) error {
	// Set up idle timeout timer if configured.
	// idleCh is nil when idle timeout is disabled — a nil channel in
	// a select case is never ready, so the branch is effectively skipped.
	var idleCh <-chan time.Time
	if app.cfg.Daemon.IdleTimeout > 0 {
		idleTimer := time.NewTimer(time.Duration(app.cfg.Daemon.IdleTimeout) * time.Second)
		defer idleTimer.Stop()
		idleCh = idleTimer.C
	}

	var pamCh <-chan time.Time
	if app.hasPAMDatabase() {
		pamTicker := time.NewTicker(2 * time.Second)
		defer pamTicker.Stop()
		pamCh = pamTicker.C
	}

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				slog.Info("received shutdown signal", "signal", sig)
				return nil
			case syscall.SIGHUP:
				slog.Info("received SIGHUP, reloading config")
				if err := app.reloadConfig(); err != nil {
					slog.Error("config reload failed", "error", err)
				}
			}

		case evt := <-eventCh:
			app.handlePoolEvent(evt)

		case <-idleCh:
			slog.Info("idle timeout reached, locking all databases")
			if err := app.pool.LockAll(); err != nil {
				slog.Error("idle lock failed", "error", err)
			}

		case <-pamCh:
			app.tryPAMAutoUnlock()
		}
	}
}

// handlePoolEvent dispatches database pool events to all interested services.
func (app *DaemonApp) handlePoolEvent(evt dbpool.Event) {
	switch evt.Type {
	case dbpool.EventDatabaseUnlocked:
		slog.Info("database unlocked", "name", evt.Name, "uuid", evt.UUID)

		// Notify Secret Service.
		if app.secSvc != nil {
			app.secSvc.HandlePoolEvent(evt)
		}

		// Notify SSH agent — auto-add keys from this database.
		if app.sshAgent != nil {
			odb, err := app.pool.Get(evt.UUID)
			if err == nil {
				app.sshAgent.OnDatabaseUnlocked(odb)
			}
		}
		if app.sshClient != nil {
			odb, err := app.pool.Get(evt.UUID)
			if err == nil {
				app.sshClient.OnDatabaseUnlocked(odb)
			}
		}

	case dbpool.EventDatabaseLocked:
		slog.Info("database locked", "name", evt.Name, "uuid", evt.UUID)

		if app.secSvc != nil {
			app.secSvc.HandlePoolEvent(evt)
		}

		if app.sshAgent != nil {
			odb, err := app.pool.Get(evt.UUID)
			if err == nil {
				app.sshAgent.OnDatabaseLocked(odb)
			}
		}
		if app.sshClient != nil {
			odb, err := app.pool.Get(evt.UUID)
			if err == nil {
				app.sshClient.OnDatabaseLocked(odb)
			}
		}

	case dbpool.EventDatabaseReloaded:
		slog.Info("database file changed on disk", "name", evt.Name, "uuid", evt.UUID)

		if app.secSvc != nil {
			app.secSvc.HandlePoolEvent(evt)
		}

	case dbpool.EventDatabaseError:
		slog.Error("database error", "name", evt.Name, "uuid", evt.UUID, "error", evt.Err)
	}
}

// autoUnlock attempts to unlock all databases that have auto_unlock=true.
func (app *DaemonApp) autoUnlock() {
	// PAM auto-unlock consumes a one-shot login token and is only supported for
	// the default database. Try it first so the fresh default DB is available to
	// Secret Service clients as soon as possible.
	app.tryPAMAutoUnlock()

	for _, db := range app.cfg.Databases {
		if !db.AutoUnlock {
			slog.Debug("skipping locked database", "name", db.Name, "path", db.Path)
			continue
		}
		if db.UnlockCredential == "pam" {
			continue
		}

		cred, err := resolveCredential(db)
		if err != nil {
			slog.Warn("auto-unlock skipped",
				"name", db.Name,
				"path", db.Path,
				"credential", db.UnlockCredential,
				"reason", err.Error())
			continue
		}

		uuid, err := app.pool.Open(db.Path, cred)
		if err != nil {
			slog.Warn("auto-unlock failed",
				"name", db.Name,
				"path", db.Path,
				"error", err)
			continue
		}

		slog.Info("auto-unlocked database",
			"name", db.Name,
			"uuid", uuid)
	}
}

// reloadConfig reloads the configuration file and re-applies settings.
func (app *DaemonApp) reloadConfig() error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	slog.Info("config reloaded",
		"log_level", cfg.Daemon.LogLevel,
		"databases", len(cfg.Databases),
	)
	app.cfg = cfg
	if app.secSvc != nil {
		app.secSvc.UpdateConfig(cfg.SecretService)
	}

	// Re-apply log level.
	level, _ := parseLogLevel(cfg.Daemon.LogLevel)
	if cfg.Daemon.LogToJournald {
		slog.SetDefault(slog.New(newJournaldHandler(level)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		})))
	}

	return nil
}

// resolveCredential creates a dbpool.Credential from a DatabaseConfig.
func resolveCredential(db config.DatabaseConfig) (dbpool.Credential, error) {
	switch db.UnlockCredential {
	case "none":
		return dbpool.Credential{Kind: dbpool.CredentialNone}, nil

	case "keyfile":
		if db.Keyfile == "" {
			return dbpool.Credential{}, fmt.Errorf("keyfile path not configured")
		}
		return dbpool.KeyfileCredential(db.Keyfile), nil

	case "yubikey":
		if db.YubikeySlot <= 0 {
			return dbpool.Credential{}, fmt.Errorf("yubikey slot not configured")
		}
		return dbpool.YubiKeyCredential(db.YubikeySlot), nil

	case "systemd-credential":
		if db.SystemdCredentialName == "" {
			return dbpool.Credential{}, fmt.Errorf("systemd_credential_name not configured")
		}
		credDir := os.Getenv("CREDENTIALS_DIRECTORY")
		if credDir == "" {
			return dbpool.Credential{}, fmt.Errorf("CREDENTIALS_DIRECTORY not set (not running under systemd with LoadCredential=?)")
		}
		data, err := os.ReadFile(filepath.Join(credDir, db.SystemdCredentialName))
		if err != nil {
			return dbpool.Credential{}, fmt.Errorf("read systemd credential %s: %w", db.SystemdCredentialName, err)
		}
		ss, err := security.NewSecureString(string(data))
		if err != nil {
			return dbpool.Credential{}, err
		}
		return dbpool.PasswordCredential(ss), nil

	case "secret-service":
		// TODO: query existing Secret Service for the password.
		return dbpool.Credential{}, fmt.Errorf("secret-service credential source not yet implemented")

	case "pam":
		return dbpool.Credential{}, fmt.Errorf("pam credential source is handled by daemon auto-unlock")

	case "prompt", "":
		return dbpool.Credential{}, fmt.Errorf("requires manual unlock via kpxcctl")

	default:
		return dbpool.Credential{}, fmt.Errorf("unknown credential type: %s", db.UnlockCredential)
	}
}

// parseLogLevel converts a string log level to slog.Level.
func parseLogLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q, using info", level)
	}
}
