//go:build linux

package sshagent

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/metalgrid/kpxcd/internal/config"
)

// LoadedKey tracks a key that has been added to the SSH agent,
// along with its constraints and metadata.
type LoadedKey struct {
	Key        *Key
	Lifetime   uint32 // 0 = unlimited
	Confirm    bool
	AutoRemove bool   // remove when database locks
	DBUUID     string // database UUID
	EntryUUID  string // entry UUID
}

// IdentityManager manages SSH keys loaded into the agent.
// It is thread-safe.
type IdentityManager struct {
	config *config.SSHAgentConfig
	mu     sync.RWMutex
	keys   map[string]*LoadedKey // fingerprint -> LoadedKey
}

// NewIdentityManager creates a new identity manager.
func NewIdentityManager(cfg *config.SSHAgentConfig) *IdentityManager {
	return &IdentityManager{
		config: cfg,
		keys:   make(map[string]*LoadedKey),
	}
}

// AddIdentity adds a key to the agent.
func (m *IdentityManager) AddIdentity(key *Key, lifetime uint32, confirm bool, autoRemove bool, dbUUID string, entryUUID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fp := key.Fingerprint()
	if _, exists := m.keys[fp]; exists {
		slog.Debug("SSH agent: key already loaded, replacing",
			"fingerprint", fp)
	}

	m.keys[fp] = &LoadedKey{
		Key:        key,
		Lifetime:   lifetime,
		Confirm:    confirm,
		AutoRemove: autoRemove,
		DBUUID:     dbUUID,
		EntryUUID:  entryUUID,
	}
	return nil
}

// RemoveIdentity removes a key by its fingerprint.
func (m *IdentityManager) RemoveIdentity(fingerprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[fingerprint]; !exists {
		return fmt.Errorf("sshagent: key not found: %s", fingerprint)
	}
	delete(m.keys, fingerprint)
	return nil
}

// RemoveAllIdentities removes all keys from the agent.
func (m *IdentityManager) RemoveAllIdentities() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = make(map[string]*LoadedKey)
}

// ListIdentities returns all loaded keys.
func (m *IdentityManager) ListIdentities() []*LoadedKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*LoadedKey, 0, len(m.keys))
	for _, lk := range m.keys {
		result = append(result, lk)
	}
	return result
}

// FindIdentityByFingerprint finds a key by its SHA256 fingerprint.
func (m *IdentityManager) FindIdentityByFingerprint(fp string) *LoadedKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keys[fp]
}

// FindIdentityByBlob finds a key by its public key blob.
func (m *IdentityManager) FindIdentityByBlob(blob []byte) *LoadedKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, lk := range m.keys {
		if equalBytes(lk.Key.Blob, blob) {
			return lk
		}
	}
	return nil
}

// RemoveIdentitiesForDatabase removes all keys belonging to a specific database.
func (m *IdentityManager) RemoveIdentitiesForDatabase(dbUUID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for fp, lk := range m.keys {
		if lk.DBUUID == dbUUID && lk.AutoRemove {
			delete(m.keys, fp)
		}
	}
}

// Count returns the number of loaded keys.
func (m *IdentityManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.keys)
}

// equalBytes compares two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
