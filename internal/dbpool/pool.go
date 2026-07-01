//go:build linux

// Package dbpool manages open KeePass databases with secure credential handling.
package dbpool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/security"
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
	mu          sync.RWMutex
	UUID        string
	Name        string
	Path        string
	Locked      bool
	Db          *gokeepasslib.Database
	Fingerprint FileFingerprint
	Watcher     *fileWatcher
}

// Lock acquires a write lock on the database for modifications.
func (o *OpenDatabase) Lock() { o.mu.Lock() }

// Unlock releases a write lock on the database.
func (o *OpenDatabase) Unlock() { o.mu.Unlock() }

// RLock acquires a read lock on the database for safe concurrent access.
func (o *OpenDatabase) RLock() { o.mu.RLock() }

// RUnlock releases a read lock on the database.
func (o *OpenDatabase) RUnlock() { o.mu.RUnlock() }

// RootEntries returns all entries recursively from the root group,
// excluding entries in the recycle bin.
func (o *OpenDatabase) RootEntries() []gokeepasslib.Entry {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.Db == nil || o.Db.Content == nil || o.Db.Content.Root == nil {
		return nil
	}
	recycleBinUUID := RecycleBinUUIDForDB(o.Db)
	var entries []gokeepasslib.Entry
	for i := range o.Db.Content.Root.Groups {
		collectEntries(&o.Db.Content.Root.Groups[i], recycleBinUUID, &entries)
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

// RecycleBinUUIDForDB returns the recycle bin UUID from database metadata,
// or the zero UUID if none is configured.
func RecycleBinUUIDForDB(db *gokeepasslib.Database) gokeepasslib.UUID {
	if db == nil || db.Content == nil || db.Content.Meta == nil {
		return gokeepasslib.UUID{}
	}
	return db.Content.Meta.RecycleBinUUID
}

// IsRecycled checks if a group is the recycle bin, either by the default
// KeePassXC name or by matching the configured recycle bin UUID.
func IsRecycled(group *gokeepasslib.Group, recycleBinUUID gokeepasslib.UUID) bool {
	if group.Name == "Recycle Bin" {
		return true
	}
	if recycleBinUUID != (gokeepasslib.UUID{}) && group.UUID == recycleBinUUID {
		return true
	}
	return false
}

// collectEntries recursively collects all entries from non-recycled groups.
func collectEntries(group *gokeepasslib.Group, recycleBinUUID gokeepasslib.UUID, entries *[]gokeepasslib.Entry) {
	if IsRecycled(group, recycleBinUUID) {
		return
	}
	for i := range group.Entries {
		*entries = append(*entries, group.Entries[i])
	}
	for i := range group.Groups {
		collectEntries(&group.Groups[i], recycleBinUUID, entries)
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
		creds, err := buildCredentials(cred)
		if err != nil {
			openErr = fmt.Errorf("dbpool: credentials %s: %w", path, err)
			return
		}
		db.Credentials = creds

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

	fingerprint, err := FingerprintFile(path)
	if err != nil {
		return "", fmt.Errorf("dbpool: fingerprint %s: %w", path, err)
	}

	odb := &OpenDatabase{
		UUID:        uuid,
		Name:        filepath.Base(path),
		Path:        path,
		Locked:      false,
		Db:          db,
		Fingerprint: fingerprint,
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
		select {
		case p.event <- Event{Type: EventDatabaseUnlocked, UUID: uuid, Name: odb.Name, Path: path}:
		default:
		}
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
		wipeDatabaseContent(odb.Db)
		odb.Db = nil
	})
	odb.Locked = true

	// Stop file watcher.
	if odb.Watcher != nil {
		odb.Watcher.cancel()
		<-odb.Watcher.done
		odb.Watcher = nil
	}

	if p.event != nil {
		select {
		case p.event <- Event{Type: EventDatabaseLocked, UUID: uuid, Name: odb.Name, Path: odb.Path}:
		default:
		}
	}

	return nil
}

// LockAll locks every unlocked database in the pool.
func (p *DatabasePool) LockAll() error {
	p.mu.RLock()
	uuids := make([]string, 0, len(p.dbs))
	for uuid, odb := range p.dbs {
		odb.mu.RLock()
		locked := odb.Locked
		odb.mu.RUnlock()
		if !locked {
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
// Any intermediate password copies are wiped before returning.
func buildCredentials(cred Credential) (*gokeepasslib.DBCredentials, error) {
	switch cred.Kind {
	case CredentialPassword:
		if cred.Password == nil {
			return nil, nil
		}
		pw := cred.Password.Bytes()
		defer security.Wipe(pw)
		return gokeepasslib.NewPasswordCredentials(string(pw)), nil
	case CredentialKeyfile:
		c, err := gokeepasslib.NewKeyCredentials(cred.Keyfile)
		if err != nil {
			return nil, fmt.Errorf("keyfile %s: %w", cred.Keyfile, err)
		}
		return c, nil
	case CredentialPasswordAndKeyfile:
		var pw []byte
		if cred.Password != nil {
			pw = cred.Password.Bytes()
		}
		defer security.Wipe(pw)
		c, err := gokeepasslib.NewPasswordAndKeyCredentials(string(pw), cred.Keyfile)
		if err != nil {
			return nil, fmt.Errorf("password+keyfile %s: %w", cred.Keyfile, err)
		}
		return c, nil
	default:
		return nil, nil
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

// watchFile monitors a file for changes using fsnotify/inotify and sends
// reload events when the database file is modified.
func watchFile(ctx context.Context, path string, eventCh chan Event, uuid string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("dbpool: failed to create file watcher", "path", path, "error", err)
		return
	}
	defer watcher.Close()

	if err := addWatch(watcher, path); err != nil {
		slog.Warn("dbpool: failed to watch database file", "path", path, "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !isWatchEventForFile(evt, path) {
				continue
			}
			// Re-add the watch if the file was removed or renamed; on Linux
			// inotify stops watching a file once it is unlinked.
			if evt.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				_ = watcher.Remove(path)
				_ = watcher.Remove(filepath.Dir(path))
				if err := waitForRecreate(ctx, path); err != nil {
					return
				}
				if err := addWatch(watcher, path); err != nil {
					slog.Warn("dbpool: failed to re-watch database file", "path", path, "error", err)
					return
				}
			}
			if eventCh != nil {
				select {
				case eventCh <- Event{Type: EventDatabaseReloaded, UUID: uuid, Path: path}:
				case <-ctx.Done():
					return
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("dbpool: file watcher error", "path", path, "error", err)
		}
	}
}

// addWatch watches both the file and its parent directory. Watching the
// directory is necessary to detect renames/removals and re-creations.
func addWatch(watcher *fsnotify.Watcher, path string) error {
	if err := watcher.Add(path); err != nil {
		return fmt.Errorf("watch file: %w", err)
	}
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return fmt.Errorf("watch parent dir: %w", err)
	}
	return nil
}

// isWatchEventForFile returns true if the fsnotify event concerns path.
func isWatchEventForFile(evt fsnotify.Event, path string) bool {
	if evt.Name == path {
		return evt.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0
	}
	// Events on the parent directory may report the basename only on some systems.
	if filepath.Base(evt.Name) == filepath.Base(path) {
		return evt.Op&(fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0
	}
	return false
}

// waitForRecreate polls briefly for path to reappear after a rename/remove.
func waitForRecreate(ctx context.Context, path string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timeout waiting for %s to reappear", path)
		case <-ticker.C:
			if _, err := os.Stat(path); err == nil {
				return nil
			}
		}
	}
}
