//go:build linux

package sshagent

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/user/kpxcd/internal/config"
	"github.com/user/kpxcd/internal/dbpool"
	"golang.org/x/crypto/ssh/agent"
)

// AgentClient connects to an existing OpenSSH agent (via SSH_AUTH_SOCK)
// and pushes KeePass SSH keys into it. This is "client mode" as opposed
// to "agent mode" where kpxcd runs its own agent server.
type AgentClient struct {
	mu     sync.Mutex
	socket string
	config *config.SSHAgentConfig
	keys   map[string]*Key // fingerprint -> key we added
}

// NewAgentClient creates a new client connected to the SSH_AUTH_SOCK agent.
func NewAgentClient(cfg *config.SSHAgentConfig) (*AgentClient, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, fmt.Errorf("sshagent: SSH_AUTH_SOCK not set")
	}
	return &AgentClient{
		socket: sock,
		config: cfg,
		keys:   make(map[string]*Key),
	}, nil
}

// OnDatabaseUnlocked extracts SSH keys from a newly unlocked database
// and adds them to the upstream agent.
func (c *AgentClient) OnDatabaseUnlocked(db *dbpool.OpenDatabase) {
	if !c.config.Enabled {
		return
	}

	keys, err := ExtractKeysFromDatabase(db.Db)
	if err != nil {
		slog.Warn("SSH agent client: failed to extract keys from database",
			"db", db.Name, "error", err)
		return
	}

	slog.Info("SSH agent client: extracted keys from database",
		"db", db.Name, "count", len(keys))

	var added, failed int
	for _, key := range keys {
		key.SetDBUUID(db.UUID)

		if err := c.AddKey(key); err != nil {
			slog.Warn("SSH agent client: failed to add key",
				"fingerprint", key.Fingerprint(), "error", err)
			failed++
		} else {
			slog.Info("SSH agent client: added key",
				"fingerprint", key.Fingerprint(),
				"type", key.Format,
				"comment", key.Comment)
			added++
		}
	}

	if added == 0 && len(keys) > 0 {
		slog.Warn("SSH agent client: no keys were added to agent",
			"db", db.Name, "extracted", len(keys), "failed", failed)
	}
}

// OnDatabaseLocked removes SSH keys belonging to a locked database
// from the upstream agent.
func (c *AgentClient) OnDatabaseLocked(db *dbpool.OpenDatabase) {
	if !c.config.Enabled {
		return
	}
	if c.config.RemoveOnLock {
		c.RemoveKeysForDB(db.UUID)
		slog.Info("SSH agent client: removed keys for locked database", "uuid", db.UUID)
	}
}

// AddKey adds a key to the upstream ssh-agent.
func (c *AgentClient) AddKey(key *Key) error {
	if key.PrivateKey == nil {
		return fmt.Errorf("cannot add key without private key material (encrypted key?)")
	}

	conn, err := net.Dial("unix", c.socket)
	if err != nil {
		return fmt.Errorf("connect to agent: %w", err)
	}
	defer conn.Close()

	added := agent.AddedKey{
		PrivateKey:       key.PrivateKey,
		Comment:          key.Comment,
		LifetimeSecs:     uint32(c.config.Lifetime),
		ConfirmBeforeUse: c.config.ConfirmOnUse,
	}
	extAgent := agent.NewClient(conn)
	if err := extAgent.Add(added); err != nil {
		return fmt.Errorf("agent refused key: %w", err)
	}

	c.mu.Lock()
	c.keys[key.Fingerprint()] = key
	c.mu.Unlock()

	return nil
}

// RemoveKey removes a key from the upstream ssh-agent by fingerprint.
func (c *AgentClient) RemoveKey(key *Key) error {
	return c.removeByFingerprint(key.Fingerprint())
}

// RemoveAllKeys removes every key that was added by this client.
func (c *AgentClient) RemoveAllKeys() {
	c.mu.Lock()
	fps := make([]string, 0, len(c.keys))
	for fp := range c.keys {
		fps = append(fps, fp)
	}
	c.mu.Unlock()

	for _, fp := range fps {
		if err := c.removeByFingerprint(fp); err != nil {
			slog.Warn("SSH agent client: failed to remove key", "fingerprint", fp, "error", err)
		}
	}
}

// RemoveKeysForDB removes all keys belonging to a specific database.
func (c *AgentClient) RemoveKeysForDB(dbUUID string) {
	c.mu.Lock()
	fps := make([]string, 0)
	for fp, key := range c.keys {
		if key.DBUUID() == dbUUID {
			fps = append(fps, fp)
		}
	}
	c.mu.Unlock()

	for _, fp := range fps {
		if err := c.removeByFingerprint(fp); err != nil {
			slog.Warn("SSH agent client: failed to remove key for DB", "fingerprint", fp, "error", err)
		}
	}
}

// Close removes all tracked keys from the agent and clears state.
func (c *AgentClient) Close() {
	c.RemoveAllKeys()
}

func (c *AgentClient) removeByFingerprint(fp string) error {
	c.mu.Lock()
	key, ok := c.keys[fp]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Always clear tracking — if the agent is gone, the keys are gone too.
	defer func() {
		c.mu.Lock()
		delete(c.keys, fp)
		c.mu.Unlock()
	}()

	pub := key.PublicKey()
	if pub == nil {
		return fmt.Errorf("cannot remove key, no public key available")
	}

	conn, err := net.Dial("unix", c.socket)
	if err != nil {
		slog.Debug("SSH agent client: agent unreachable, assuming key removed", "fingerprint", fp)
		return nil
	}
	defer conn.Close()

	extAgent := agent.NewClient(conn)
	if err := extAgent.Remove(pub); err != nil {
		slog.Warn("SSH agent client: agent refused removal", "fingerprint", fp, "error", err)
	}

	return nil
}
