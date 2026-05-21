//go:build linux

package daemon

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/user/kpxcd/internal/pamcred"
	"github.com/user/kpxcd/internal/security"
	"github.com/user/kpxcd/internal/xdg"
)

// PAMSocketServer listens on a Unix domain socket for a one-shot PAM
// derived-key handoff. When a 32-byte derived key is received, it is
// passed to unlockOrBootstrapWithPAM and the listener is closed.
//
// The socket may be provided by systemd socket activation (kpxcd-pam.socket)
// or created directly by the daemon if systemd is not managing it.
type PAMSocketServer struct {
	app      *DaemonApp
	listener net.Listener
	mu       sync.Mutex
	done     chan struct{}
}

// NewPAMSocketServer creates a new PAM socket server for the given app.
func NewPAMSocketServer(app *DaemonApp) *PAMSocketServer {
	return &PAMSocketServer{
		app:  app,
		done: make(chan struct{}),
	}
}

// Listen creates the Unix domain socket and starts listening.
// If systemd has passed a socket via fd activation (kpxcd-pam.socket),
// that socket is used directly. Otherwise, a new socket is created.
func (s *PAMSocketServer) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	listener, err := s.systemdOrDirectListener()
	if err != nil {
		return err
	}

	s.listener = listener
	slog.Info("PAM socket listening", "socket", listener.Addr().String())

	go s.serve()
	return nil
}

// systemdOrDirectListener returns a listener from systemd socket activation
// if one was provided, otherwise creates a new Unix domain socket listener.
func (s *PAMSocketServer) systemdOrDirectListener() (net.Listener, error) {
	// Check for systemd socket activation.
	listeners, err := activation.Listeners()
	if err != nil {
		slog.Debug("PAM socket: systemd activation check failed", "error", err)
		// Fall through to direct creation.
	} else if len(listeners) > 0 {
		slog.Info("PAM socket: using systemd-provided listener")
		return listeners[0], nil
	}

	// No systemd socket; create our own.
	socketPath, err := xdg.PAMSocketPath()
	if err != nil {
		return nil, fmt.Errorf("pamsocket: resolve socket path: %w", err)
	}

	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("pamsocket: create socket directory: %w", err)
	}

	// Remove any stale socket from a previous session.
	os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("pamsocket: listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("pamsocket: chmod socket: %w", err)
	}

	return l, nil
}

// serve accepts connections and dispatches each to a goroutine.
func (s *PAMSocketServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				slog.Warn("PAM socket accept error", "error", err)
				continue
			}
		}

		go s.handleConn(conn)
	}
}

func (s *PAMSocketServer) handleConn(conn net.Conn) {
	defer conn.Close()

	token := make([]byte, pamcred.PAMTokenLen)
	if _, err := io.ReadFull(conn, token); err != nil {
		slog.Warn("PAM socket read error", "error", err)
		return
	}
	defer security.Wipe(token)

	slog.Debug("PAM token received over socket")

	db := s.app.defaultDatabase()
	if db == nil || !db.AutoUnlock || db.UnlockCredential != "pam" {
		slog.Debug("PAM auto-unlock skipped: no PAM database configured")
		return
	}
	if s.app.isDatabaseOpen(db.Path) {
		slog.Debug("PAM auto-unlock skipped: database already open")
		return
	}

	if err := s.app.unlockOrBootstrapWithPAM(*db, token); err != nil {
		slog.Warn("pam auto-unlock failed", "name", db.Name, "path", db.Path, "error", err)
	}
}

// Close shuts down the listener.
func (s *PAMSocketServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	close(s.done)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
