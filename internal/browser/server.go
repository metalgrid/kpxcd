//go:build linux

// Package browser implements the KeePassXC browser extension protocol.
// The extension communicates via keepassxc-proxy over a Unix domain socket
// using NaCl-encrypted JSON messages.
package browser

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
)

// Server listens on the KeePassXC browser socket and dispatches protocol
// messages to handlers.
type Server struct {
	config     *config.BrowserConfig
	pool       *dbpool.DatabasePool
	listener   net.Listener
	socketPath string
	mu         sync.Mutex
	done       chan struct{}
}

// NewServer creates a new browser extension protocol server.
func NewServer(cfg *config.BrowserConfig, pool *dbpool.DatabasePool, socketPath string) *Server {
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}
	return &Server{
		config:     cfg,
		pool:       pool,
		socketPath: socketPath,
		done:       make(chan struct{}),
	}
}

// Listen starts listening on the Unix domain socket.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("browser: failed to create socket directory: %w", err)
	}

	// Remove stale socket.
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("browser: failed to listen on %s: %w", s.socketPath, err)
	}
	s.listener = ln
	return nil
}

// Serve accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.done:
			return nil
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.done:
				return nil
			default:
				slog.Warn("browser: accept error", "error", err)
				continue
			}
		}

		go s.handleConn(ctx, conn)
	}
}

// Close shuts down the server and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	close(s.done)
	var err error
	if s.listener != nil {
		err = s.listener.Close()
		s.listener = nil
	}
	os.Remove(s.socketPath)
	return err
}

// SocketPath returns the resolved socket path.
func (s *Server) SocketPath() string {
	return s.socketPath
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	slog.Debug("browser: new connection", "remote", conn.RemoteAddr())
	_ = ctx // TODO: use in protocol dispatch
	// TODO: read length-prefixed message, dispatch to handler, write response
}

func defaultSocketPath() string {
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		xdg = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	return filepath.Join(xdg, "app/org.keepassxc.KeePassXC", "browser.sock")
}
