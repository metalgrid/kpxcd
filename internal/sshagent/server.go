//go:build linux

package sshagent

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
	"github.com/metalgrid/kpxcd/internal/security"
	"golang.org/x/crypto/ssh"
)

// AgentServer implements an OpenSSH-compatible SSH agent server
// that serves keys from KeePass databases over a Unix domain socket.
type AgentServer struct {
	config     *config.SSHAgentConfig
	pool       *dbpool.DatabasePool
	manager    *IdentityManager
	listener   net.Listener
	socketPath string
	mu         sync.Mutex
	done       chan struct{}
	closeOnce  sync.Once
}

// NewAgentServer creates a new SSH agent server.
func NewAgentServer(cfg *config.SSHAgentConfig, pool *dbpool.DatabasePool, socketPath string) *AgentServer {
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}
	return &AgentServer{
		config:     cfg,
		pool:       pool,
		manager:    NewIdentityManager(cfg),
		socketPath: socketPath,
		done:       make(chan struct{}),
	}
}

// Manager returns the identity manager for this agent.
func (s *AgentServer) Manager() *IdentityManager {
	return s.manager
}

// Listen starts listening on the Unix domain socket.
func (s *AgentServer) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("sshagent: failed to create socket directory: %w", err)
	}

	os.Remove(s.socketPath)

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("sshagent: failed to listen on %s: %w", s.socketPath, err)
	}

	if err := os.Chmod(s.socketPath, 0600); err != nil {
		l.Close()
		return fmt.Errorf("sshagent: failed to set socket permissions: %w", err)
	}

	s.listener = l
	slog.Info("SSH agent listening", "socket", s.socketPath)
	return nil
}

// Serve accepts and serves client connections until the context is cancelled
// or Close() is called.
func (s *AgentServer) Serve(ctx context.Context) error {
	if s.listener == nil {
		return fmt.Errorf("sshagent: not listening")
	}

	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				// Listener closed — check if we're shutting down.
				select {
				case <-s.done:
					return
				case <-ctx.Done():
					return
				default:
				}
				// Transient error — log and retry.
				slog.Error("SSH agent accept error", "error", err)
				continue
			}
			go s.handleConn(ctx, conn)
		}
	}()

	// Block until context cancelled or Close() called.
	select {
	case <-ctx.Done():
	case <-s.done:
	}
	return nil
}

// Close closes the listener and removes the socket file.
func (s *AgentServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeOnce.Do(func() { close(s.done) })

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return err
		}
	}
	os.Remove(s.socketPath)
	slog.Info("SSH agent stopped")
	return nil
}

// SocketPath returns the path to the Unix socket.
func (s *AgentServer) SocketPath() string {
	return s.socketPath
}

// handleConn serves a single SSH agent client connection.
func (s *AgentServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := readMessage(conn)
		if err != nil {
			return
		}

		resp, err := s.processMessage(msg)
		if err != nil {
			slog.Debug("SSH agent message error", "error", err)
			_ = writeFailure(conn)
			return
		}

		if err := writeMessage(conn, resp); err != nil {
			return
		}
	}
}

// processMessage handles a single SSH agent protocol message.
func (s *AgentServer) processMessage(msg []byte) ([]byte, error) {
	msgType, payload := decodeMessageType(msg)

	switch msgType {
	case SSHAgentCRequestIdentities:
		return s.handleListIdentities()
	case SSHAgentCSignRequest:
		return s.handleSignRequest(payload)
	case SSHAgentCExtension:
		// OpenSSH clients may send optional extension requests such as
		// session-bind@openssh.com before fetching identities. We don't
		// implement extensions yet, but per PROTOCOL.agent unsupported
		// extensions must return SSH_AGENT_FAILURE without closing the
		// connection so clients can continue with the base protocol.
		return []byte{SSHAgentFailure}, nil
	case SSHAgentCAddIdentity:
		return s.handleAddIdentity(payload, false)
	case SSHAgentCAddIdConstrained:
		return s.handleAddIdentity(payload, true)
	case SSHAgentCRemoveIdentity:
		return s.handleRemoveIdentity(payload)
	case SSHAgentCRemoveAllIdentities:
		return s.handleRemoveAllIdentities()
	case SSHAgentCRemoveAllRsaIdentities:
		return []byte{SSHAgentSuccess}, nil
	default:
		slog.Debug("SSH agent: unknown message type", "type", msgType)
		return nil, fmt.Errorf("unknown message type: %d", msgType)
	}
}

// handleListIdentities returns all loaded identities.
func (s *AgentServer) handleListIdentities() ([]byte, error) {
	keys := s.manager.ListIdentities()
	blobs := make([][]byte, len(keys))
	comments := make([]string, len(keys))

	for i, lk := range keys {
		blobs[i] = lk.Key.Blob
		comments[i] = lk.Key.Comment
	}

	return encodeIdentitiesAnswer(blobs, comments), nil
}

// handleSignRequest signs data with a requested key.
func (s *AgentServer) handleSignRequest(payload []byte) ([]byte, error) {
	keyBlob, rest := decodeString(payload)
	if keyBlob == nil {
		return nil, fmt.Errorf("sshagent: failed to parse sign request key blob")
	}
	data, rest := decodeString(rest)
	if data == nil {
		return nil, fmt.Errorf("sshagent: failed to parse sign request data")
	}
	flags := uint32(0)
	if len(rest) > 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("sshagent: truncated sign request flags")
		}
		flags, rest = decodeUint32(rest)
		if rest == nil {
			return nil, fmt.Errorf("sshagent: failed to parse sign request flags")
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("sshagent: trailing bytes in sign request")
		}
	}

	key := s.manager.FindIdentityByBlob(keyBlob)
	if key == nil {
		return nil, fmt.Errorf("sshagent: key not found")
	}

	if key.Confirm {
		slog.Info("SSH agent: confirm constraint (auto-allowed)", "fingerprint", key.Key.Fingerprint())
	}

	algorithm, err := signatureAlgorithmForFlags(flags)
	if err != nil {
		return nil, err
	}

	// Sign inside runtime/secret.Do to protect private key material.
	var sig *ssh.Signature
	var signErr error
	security.Do(func() {
		if algorithm != "" {
			algorithmSigner, ok := key.Key.Signer.(ssh.AlgorithmSigner)
			if !ok {
				signErr = fmt.Errorf("sshagent: signer does not support algorithm %s", algorithm)
				return
			}
			sig, signErr = algorithmSigner.SignWithAlgorithm(nil, data, algorithm)
			return
		}
		sig, signErr = key.Key.Sign(data)
	})
	if signErr != nil {
		return nil, fmt.Errorf("sshagent: sign failed: %w", signErr)
	}

	sigBlob := ssh.Marshal(sig)
	resp := make([]byte, 0, 1+4+len(sigBlob))
	resp = append(resp, SSHAgentSignResponse)
	resp = encodeString(resp, sigBlob)
	return resp, nil
}

func signatureAlgorithmForFlags(flags uint32) (string, error) {
	if flags&SSHAgentSignFlagReserved != 0 {
		return "", fmt.Errorf("sshagent: unsupported reserved sign flag")
	}
	rsa256 := flags&SSHAgentSignFlagRSASHA256 != 0
	rsa512 := flags&SSHAgentSignFlagRSASHA512 != 0
	if rsa256 && rsa512 {
		return "", fmt.Errorf("sshagent: conflicting RSA signature flags")
	}
	known := uint32(SSHAgentSignFlagReserved | SSHAgentSignFlagRSASHA256 | SSHAgentSignFlagRSASHA512)
	if flags&^known != 0 {
		return "", fmt.Errorf("sshagent: unsupported sign flags 0x%x", flags)
	}
	if rsa256 {
		return ssh.KeyAlgoRSASHA256, nil
	}
	if rsa512 {
		return ssh.KeyAlgoRSASHA512, nil
	}
	return "", nil
}

// handleAddIdentity handles key addition from external clients (not primary use case).
func (s *AgentServer) handleAddIdentity(payload []byte, constrained bool) ([]byte, error) {
	// External key addition is not the primary use case.
	// Keys come from KeePass databases via the IdentityManager.
	slog.Warn("SSH agent: external key addition not supported")
	return []byte{SSHAgentFailure}, nil
}

// handleRemoveIdentity removes a key by its public blob.
func (s *AgentServer) handleRemoveIdentity(payload []byte) ([]byte, error) {
	keyBlob, rest := decodeString(payload)
	if keyBlob == nil || len(rest) != 0 {
		return []byte{SSHAgentFailure}, nil
	}

	key := s.manager.FindIdentityByBlob(keyBlob)
	if key == nil {
		return []byte{SSHAgentFailure}, nil
	}

	s.manager.RemoveIdentity(key.Key.Fingerprint())
	return []byte{SSHAgentSuccess}, nil
}

// handleRemoveAllIdentities removes all keys.
func (s *AgentServer) handleRemoveAllIdentities() ([]byte, error) {
	s.manager.RemoveAllIdentities()
	return []byte{SSHAgentSuccess}, nil
}

// OnDatabaseUnlocked adds SSH keys from a newly unlocked database.
func (s *AgentServer) OnDatabaseUnlocked(db *dbpool.OpenDatabase) {
	if !s.config.Enabled {
		return
	}

	keys, err := ExtractKeysFromDatabase(db.Db)
	if err != nil {
		slog.Warn("SSH agent: failed to extract keys from database", "error", err)
		return
	}

	for _, key := range keys {
		key.SetDBUUID(db.UUID)

		lifetime := uint32(s.config.Lifetime)
		if err := s.manager.AddIdentity(key, lifetime, s.config.ConfirmOnUse,
			s.config.RemoveOnLock, db.UUID, key.EntryUUID()); err != nil {
			slog.Warn("SSH agent: failed to add identity",
				"fingerprint", key.Fingerprint(), "error", err)
		} else {
			slog.Info("SSH agent: added key",
				"fingerprint", key.Fingerprint(),
				"type", key.Format,
				"comment", key.Comment)
		}
	}
}

// OnDatabaseLocked removes SSH keys from a locked database.
func (s *AgentServer) OnDatabaseLocked(db *dbpool.OpenDatabase) {
	if !s.config.Enabled {
		return
	}
	s.manager.RemoveIdentitiesForDatabase(db.UUID)
	slog.Info("SSH agent: removed keys for locked database", "uuid", db.UUID)
}

// resolveSocketPath determines the SSH agent socket path.
func resolveSocketPath(cfg *config.SSHAgentConfig) string {
	// Socket path is configured at the top level (DaemonConfig.SSHSocketPath).
	// We accept it via parameter here for flexibility.
	socketPath := defaultSocketPath()
	return socketPath
}

func defaultSocketPath() string {
	runDir := os.Getenv("XDG_RUNTIME_DIR")
	if runDir == "" {
		runDir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	return filepath.Join(runDir, "kpxcd", "ssh.sock")
}
