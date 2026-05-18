//go:build linux

// Package dbpool manages open KeePass databases with secure credential handling.
package dbpool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tobischo/gokeepasslib/v3"

	"github.com/user/kpxcd/internal/security"
)

// CredentialKind identifies the type of credential.
type CredentialKind int

const (
	CredentialNone CredentialKind = iota
	CredentialPassword
	CredentialKeyfile
	CredentialPasswordAndKeyfile
	CredentialYubiKey
	CredentialSystemdCredential
)

// Credential is a discriminated union for database unlock credentials.
type Credential struct {
	Kind     CredentialKind
	Password *security.SecureString // for Password, PasswordAndKeyfile
	Keyfile  string                 // path for Keyfile, PasswordAndKeyfile
	Slot     int                    // YubiKey slot (1 or 2)
	Name     string                 // systemd credential name
}

// PasswordCredential creates a password-only credential.
func PasswordCredential(password *security.SecureString) Credential {
	return Credential{Kind: CredentialPassword, Password: password}
}

// KeyfileCredential creates a keyfile-only credential.
func KeyfileCredential(path string) Credential {
	return Credential{Kind: CredentialKeyfile, Keyfile: path}
}

// PasswordKeyfileCredential creates a composite credential.
func PasswordKeyfileCredential(password *security.SecureString, keyfile string) Credential {
	return Credential{Kind: CredentialPasswordAndKeyfile, Password: password, Keyfile: keyfile}
}

// YubiKeyCredential creates a YubiKey challenge-response credential.
func YubiKeyCredential(slot int) Credential {
	return Credential{Kind: CredentialYubiKey, Slot: slot}
}

// OpenDatabase wraps a gokeepasslib.Database with metadata and lifecycle state.
type OpenDatabase struct {
	mu      sync.RWMutex
	UUID    string
	Name    string
	Path    string
	Locked  bool
	Db      *gokeepasslib.Database
	Watcher *fileWatcher
}

// Lock acquires a write lock on the database for modifications.
func (o *OpenDatabase) Lock() { o.mu.Lock() }

// Unlock releases a write lock on the database.
func (o *OpenDatabase) Unlock() { o.mu.Unlock() }

// RLock acquires a read lock on the database for safe concurrent access.
func (o *OpenDatabase) RLock() { o.mu.RLock() }

// RUnlock releases a read lock on the database.
func (o *OpenDatabase) RUnlock() { o.mu.RUnlock() }

// RootEntries returns all entries recursively from the root group.
func (o *OpenDatabase) RootEntries() []gokeepasslib.Entry {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.Db == nil || o.Db.Content == nil || o.Db.Content.Root == nil {
		return nil
	}
	var entries []gokeepasslib.Entry
	for i := range o.Db.Content.Root.Groups {
		collectEntries(&o.Db.Content.Root.Groups[i], &entries)
	}
	return entries
}

// RootGroups returns all groups from the root.
func (o *OpenDatabase) RootGroups() []gokeepasslib.Group {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.Db == nil || o.Db.Content == nil || o.Db.Content.Root == nil {
		return nil
	}
	return o.Db.Content.Root.Groups
}

// isRecycled checks if a group is the recycle bin.
// KeePassXC names the recycle bin group "Recycle Bin" by default.
func isRecycled(group *gokeepasslib.Group) bool {
	return group.Name == "Recycle Bin"
}

// collectEntries recursively collects all entries from non-recycled groups.
func collectEntries(group *gokeepasslib.Group, entries *[]gokeepasslib.Entry) {
	if isRecycled(group) {
		return
	}
	for i := range group.Entries {
		*entries = append(*entries, group.Entries[i])
	}
	for i := range group.Groups {
		collectEntries(&group.Groups[i], entries)
	}
}

// fileWatcher wraps a file watcher for a single database file.
type fileWatcher struct {
	cancel context.CancelFunc
	done   <-chan struct{}
}

// DatabasePool manages a collection of open databases.
type DatabasePool struct {
	mu    sync.RWMutex
	dbs   map[string]*OpenDatabase
	event chan Event
}

// Event represents a database pool event.
type Event struct {
	Type EventType
	UUID string
	Name string // human-readable database name
	Path string // database file path
	Err  error
}

// EventType enumerates database pool events.
type EventType int

const (
	EventDatabaseUnlocked EventType = iota
	EventDatabaseLocked
	EventDatabaseReloaded
	EventDatabaseError
)

// NewDatabasePool creates an empty database pool.
func NewDatabasePool(eventChan chan Event) *DatabasePool {
	return &DatabasePool{
		dbs:   make(map[string]*OpenDatabase),
		event: eventChan,
	}
}

// Open loads and unlocks a KeePass database from the given path using the
// provided credential. Returns the database UUID on success.
// All credential handling and decryption occur inside security.Do()
// to ensure registers and stack frames are zeroed after use.
func (p *DatabasePool) Open(path string, cred Credential) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("dbpool: open %s: %w", path, err)
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()

	// Perform credential construction, decoding, and unlock inside
	// security.Do() so that key material and derivative values are
	// zeroed from registers and stack frames before returning.
	var uuid string
	var openErr error
	security.Do(func() {
		// Set credentials before decoding — the decoder needs them
		// to derive the transformed key and decrypt the database content.
		db.Credentials = buildCredentials(cred)

		if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
			openErr = fmt.Errorf("dbpool: decode %s: %w", path, err)
			return
		}

		if err := db.UnlockProtectedEntries(); err != nil {
			openErr = fmt.Errorf("dbpool: unlock %s: %w", path, err)
			return
		}

		// Extract database UUID from the root group.
		uuid = extractUUID(db, path)
	})

	if openErr != nil {
		return "", openErr
	}

	odb := &OpenDatabase{
		UUID:   uuid,
		Name:   filepath.Base(path),
		Path:   path,
		Locked: false,
		Db:     db,
	}

	// Set up file watcher for external changes.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchFile(ctx, path, p.event, uuid)
	}()
	odb.Watcher = &fileWatcher{cancel: cancel, done: done}

	p.mu.Lock()
	p.dbs[uuid] = odb
	p.mu.Unlock()

	if p.event != nil {
		p.event <- Event{Type: EventDatabaseUnlocked, UUID: uuid, Name: odb.Name, Path: path}
	}

	return uuid, nil
}

// Lock locks a database by UUID, clearing decrypted data from memory.
func (p *DatabasePool) Lock(uuid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	odb, ok := p.dbs[uuid]
	if !ok {
		return fmt.Errorf("dbpool: database %s not found", uuid)
	}

	odb.mu.Lock()
	defer odb.mu.Unlock()

	security.Do(func() {
		odb.Db.Content = nil
	})
	odb.Locked = true

	// Stop file watcher.
	if odb.Watcher != nil {
		odb.Watcher.cancel()
		<-odb.Watcher.done
		odb.Watcher = nil
	}

	if p.event != nil {
		p.event <- Event{Type: EventDatabaseLocked, UUID: uuid, Name: odb.Name, Path: odb.Path}
	}

	return nil
}

// LockAll locks every unlocked database in the pool.
func (p *DatabasePool) LockAll() error {
	p.mu.RLock()
	uuids := make([]string, 0, len(p.dbs))
	for uuid, odb := range p.dbs {
		if !odb.Locked {
			uuids = append(uuids, uuid)
		}
	}
	p.mu.RUnlock()

	var firstErr error
	for _, uuid := range uuids {
		if err := p.Lock(uuid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Get retrieves an open database by UUID.
func (p *DatabasePool) Get(uuid string) (*OpenDatabase, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	odb, ok := p.dbs[uuid]
	if !ok {
		return nil, fmt.Errorf("dbpool: database %s not found", uuid)
	}
	return odb, nil
}

// List returns all databases in the pool.
func (p *DatabasePool) List() []*OpenDatabase {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*OpenDatabase, 0, len(p.dbs))
	for _, odb := range p.dbs {
		result = append(result, odb)
	}
	return result
}

// Close locks all databases and releases all resources.
func (p *DatabasePool) Close() error {
	err := p.LockAll()
	p.mu.Lock()
	p.dbs = make(map[string]*OpenDatabase)
	p.mu.Unlock()
	return err
}

// buildCredentials converts a Credential into gokeepasslib DBCredentials.
func buildCredentials(cred Credential) *gokeepasslib.DBCredentials {
	switch cred.Kind {
	case CredentialPassword:
		if cred.Password == nil {
			return nil
		}
		return gokeepasslib.NewPasswordCredentials(string(cred.Password.Bytes()))
	case CredentialKeyfile:
		c, _ := gokeepasslib.NewKeyCredentials(cred.Keyfile)
		return c
	case CredentialPasswordAndKeyfile:
		var pw string
		if cred.Password != nil {
			pw = string(cred.Password.Bytes())
		}
		c, _ := gokeepasslib.NewPasswordAndKeyCredentials(pw, cred.Keyfile)
		return c
	default:
		return nil
	}
}

// extractUUID extracts or derives a unique identifier for the database.
// Uses the root group UUID if available, otherwise derives from file path.
func extractUUID(db *gokeepasslib.Database, path string) string {
	if db != nil && db.Content != nil && db.Content.Root != nil &&
		len(db.Content.Root.Groups) > 0 {
		uuid := db.Content.Root.Groups[0].UUID
		if uuid != (gokeepasslib.UUID{}) {
			text, _ := uuid.MarshalText()
			return string(text)
		}
	}
	// Fallback: derive a stable UUID from the file path.
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:16])
}

// watchFile monitors a file for changes and sends reload events.
func watchFile(ctx context.Context, path string, eventCh chan Event, uuid string) {
	// Simple polling-based file watcher for the scaffold.
	// In production, use fsnotify.Watcher for efficient inotify-based watching.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lastMod time.Time
	if info, err := os.Stat(path); err == nil {
		lastMod = info.ModTime()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.ModTime().After(lastMod) {
				lastMod = info.ModTime()
				if eventCh != nil {
					eventCh <- Event{Type: EventDatabaseReloaded, UUID: uuid, Path: path}
				}
			}
		}
	}
}
