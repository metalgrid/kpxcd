//go:build linux

// Package dbpool manages open KeePass databases with secure credential handling.
package dbpool

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
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

var nextInstanceID atomic.Uint64

// OpenDatabase wraps a gokeepasslib.Database with metadata and lifecycle state.
type OpenDatabase struct {
	mu          sync.RWMutex
	UUID        string
	InstanceID  uint64 // Immutable identity of this particular open, not the file UUID.
	Name        string
	Path        string
	Locked      bool
	Db          *gokeepasslib.Database
	Fingerprint FileFingerprint
	Watcher     *fileWatcher
	// cred retains the unlock credential so the file can be re-decoded after
	// an external change (Reload). It is destroyed on Lock.
	cred Credential
}

// Lock acquires a write lock on the database for modifications.
func (o *OpenDatabase) Lock() { o.mu.Lock() }

// Unlock releases a write lock on the database.
func (o *OpenDatabase) Unlock() { o.mu.Unlock() }

// RLock acquires a read lock on the database for safe concurrent access.
func (o *OpenDatabase) RLock() { o.mu.RLock() }

// RUnlock releases a read lock on the database.
func (o *OpenDatabase) RUnlock() { o.mu.RUnlock() }

// IsLocked reports whether the database is locked. Safe for concurrent use;
// callers that need Locked and Db together must hold RLock instead.
func (o *OpenDatabase) IsLocked() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.Locked
}

// RootEntries returns all entries recursively from the root group,
// excluding entries in the recycle bin.
func (o *OpenDatabase) RootEntries() []gokeepasslib.Entry {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.RootEntriesLocked()
}

// RootEntriesLocked is RootEntries for callers already holding the
// database lock. It must not be called without RLock/Lock held.
func (o *OpenDatabase) RootEntriesLocked() []gokeepasslib.Entry {
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
	// Events are queued and forwarded to event by a dedicated dispatcher
	// goroutine: producers (Open/Lock) must never block on the consumer,
	// because the consumer calls back into the pool (Get, LockAll).
	queue   []Event
	wake    chan struct{}
	stopCh  chan struct{}
	stopped bool
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

// NewDatabasePool creates an empty database pool. Events are queued and
// forwarded to eventChan by a dispatcher goroutine, so producers never block
// on the consumer; the consumer must still drain eventChan. Close stops
// event delivery.
func NewDatabasePool(eventChan chan Event) *DatabasePool {
	p := &DatabasePool{
		dbs:    make(map[string]*OpenDatabase),
		event:  eventChan,
		wake:   make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
	if eventChan != nil {
		// The channel is captured by value: Close nils p.event under the
		// lock, and the dispatcher must not read that field.
		go p.dispatchEvents(eventChan)
	}
	return p
}

// enqueue appends an event for delivery. It never blocks: the dispatcher
// goroutine forwards queued events to the consumer channel.
func (p *DatabasePool) enqueue(ev Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enqueueLocked(ev)
}

// enqueueLocked is enqueue for callers already holding p.mu.
func (p *DatabasePool) enqueueLocked(ev Event) {
	if p.stopped || p.event == nil {
		return
	}
	p.queue = append(p.queue, ev)
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// dispatchEvents forwards queued events to the consumer until Close.
func (p *DatabasePool) dispatchEvents(eventCh chan Event) {
	for {
		select {
		case <-p.stopCh:
			return
		case <-p.wake:
		}
		p.mu.Lock()
		queue := p.queue
		p.queue = nil
		p.mu.Unlock()
		for _, ev := range queue {
			select {
			case eventCh <- ev:
			case <-p.stopCh:
				return
			}
		}
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

	uuid, db, err := decodeDatabase(f, cred)
	if err != nil {
		return "", err
	}

	// Fingerprint the same descriptor we decoded from, so the stored
	// fingerprint always matches the content in memory.
	fingerprint, err := FingerprintOpenFile(f)
	if err != nil {
		return "", fmt.Errorf("dbpool: fingerprint %s: %w", path, err)
	}

	// Retain a private copy of the credential for Reload; the caller keeps
	// ownership of the original (tests destroy it themselves).
	storedCred := cred
	if cred.Password != nil {
		ss, err := security.NewSecureString(string(cred.Password.Bytes()))
		if err != nil {
			return "", fmt.Errorf("dbpool: copy credential %s: %w", path, err)
		}
		storedCred.Password = ss
	}

	odb := &OpenDatabase{
		UUID:        uuid,
		InstanceID:  nextInstanceID.Add(1),
		Name:        filepath.Base(path),
		Path:        path,
		Locked:      false,
		Db:          db,
		Fingerprint: fingerprint,
		cred:        storedCred,
	}

	// Set up file watcher for external changes. The event channel is read
	// under the pool lock so Close's stop cannot race the watcher start.
	p.mu.RLock()
	eventCh := p.event
	p.mu.RUnlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchFile(ctx, path, eventCh, uuid)
	}()
	odb.Watcher = &fileWatcher{cancel: cancel, done: done}

	p.mu.Lock()
	// Reopening an already-open database: tear the old instance down and emit
	// Locked(old) then Unlocked(new) in this one critical section, so consumers
	// do a normal lock/unlock cycle (aliases, SSH keys, collections) and the
	// order is fixed.
	if old, ok := p.dbs[uuid]; ok {
		old.mu.Lock()
		old.destroyLocked()
		old.mu.Unlock()
		p.enqueueLocked(Event{Type: EventDatabaseLocked, UUID: uuid, Name: old.Name, Path: old.Path})
	}
	p.dbs[uuid] = odb
	p.enqueueLocked(Event{Type: EventDatabaseUnlocked, UUID: uuid, Name: odb.Name, Path: path})
	p.mu.Unlock()

	return uuid, nil
}

// destroyLocked wipes the database content, destroys the retained credential
// copy, and stops the file watcher. The caller must hold o.mu.
func (o *OpenDatabase) destroyLocked() {
	security.Do(func() {
		wipeDatabaseContent(o.Db)
		o.Db = nil
	})
	o.Locked = true
	if o.cred.Password != nil {
		o.cred.Password.Destroy()
	}
	o.cred = Credential{}
	if o.Watcher != nil {
		o.Watcher.cancel()
		<-o.Watcher.done
		o.Watcher = nil
	}
}

// Lock locks a database by UUID, clearing decrypted data from memory.
func (p *DatabasePool) Lock(uuid string) error {
	p.mu.Lock()
	odb, ok := p.dbs[uuid]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("dbpool: database %s not found", uuid)
	}

	odb.mu.Lock()
	odb.destroyLocked()

	name, path := odb.Name, odb.Path
	odb.mu.Unlock()
	// Enqueue while still holding p.mu: the state change and the event must
	// be one critical section so a reopen cannot be overtaken by this lock.
	p.enqueueLocked(Event{Type: EventDatabaseLocked, UUID: uuid, Name: name, Path: path})
	p.mu.Unlock()

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

// WithUnlockedDatabases keeps pool membership and lock transitions stable while
// visit inspects or updates unlocked databases. The callback may take database
// locks, but must not call pool methods (pool locks precede database locks).
func (p *DatabasePool) WithUnlockedDatabases(visit func([]*OpenDatabase) error) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var dbs []*OpenDatabase
	for _, db := range p.dbs {
		db.mu.RLock()
		available := !db.Locked && db.Db != nil
		db.mu.RUnlock()
		if available {
			dbs = append(dbs, db)
		}
	}
	return visit(dbs)
}

// UpdateAndSaveWithUnlockedDatabases holds pool membership stable and locks database
// contents through validation and a single target save. The target must be this
// exact open instance. Other unlocked databases are read-only in update; only
// the target may be mutated. Like UpdateAndSave, validate before mutation.
// The callback must not call pool or database methods: all locks are already held.
// Lock order is pool, then databases by InstanceID (target write, others read).
func (p *DatabasePool) UpdateAndSaveWithUnlockedDatabases(target *OpenDatabase, update func(map[*OpenDatabase]*gokeepasslib.Database) error) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if target == nil || p.dbs[target.UUID] != target {
		return fmt.Errorf("dbpool: selected registration database is unavailable")
	}
	dbs := make([]*OpenDatabase, 0, len(p.dbs))
	for _, db := range p.dbs {
		dbs = append(dbs, db)
	}
	slices.SortFunc(dbs, func(a, b *OpenDatabase) int { return cmp.Compare(a.InstanceID, b.InstanceID) })
	for _, db := range dbs {
		if db == target {
			db.mu.Lock()
		} else {
			db.mu.RLock()
		}
	}
	defer func() {
		for i := len(dbs) - 1; i >= 0; i-- {
			if dbs[i] == target {
				dbs[i].mu.Unlock()
			} else {
				dbs[i].mu.RUnlock()
			}
		}
	}()
	unlocked := make(map[*OpenDatabase]*gokeepasslib.Database)
	for _, db := range dbs {
		if !db.Locked && db.Db != nil {
			unlocked[db] = db.Db
		}
	}
	return target.updateAndSaveLocked(func(_ *gokeepasslib.Database) error { return update(unlocked) })
}

// Close locks all databases and releases all resources.
func (p *DatabasePool) Close() error {
	p.mu.Lock()
	// Stop event delivery first: the consumer (event loop) has exited by the
	// time Close runs, so queued events must not block the dispatcher.
	if !p.stopped {
		p.stopped = true
		p.event = nil
		close(p.stopCh)
	}
	p.mu.Unlock()
	err := p.LockAll()
	p.mu.Lock()
	p.dbs = make(map[string]*OpenDatabase)
	p.mu.Unlock()
	return err
}

// decodeDatabase decodes and unlocks the KDBX stream in f with cred.
// Credential construction, decoding, and unlock happen inside security.Do()
// so key material is zeroed from registers and stack frames after use.
func decodeDatabase(f *os.File, cred Credential) (string, *gokeepasslib.Database, error) {
	path := f.Name()
	db := gokeepasslib.NewDatabase()

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
		return "", nil, openErr
	}
	return uuid, db, nil
}

// Reload re-reads a database file from disk with the retained unlock
// credential, used when the file watcher reports an external modification.
// The in-memory content is replaced only when the file changed and decoding
// succeeds; on any failure the previous content is kept and an error is
// returned. It reports whether the in-memory content actually changed.
func (p *DatabasePool) Reload(uuid string) (bool, error) {
	p.mu.RLock()
	odb, ok := p.dbs[uuid]
	p.mu.RUnlock()
	if !ok {
		return false, fmt.Errorf("dbpool: database %s not found", uuid)
	}

	odb.mu.Lock()
	defer odb.mu.Unlock()
	if odb.Locked || odb.Db == nil {
		return false, fmt.Errorf("dbpool: database %s is locked", uuid)
	}

	f, err := os.Open(odb.Path)
	if err != nil {
		return false, fmt.Errorf("dbpool: reload %s: %w", odb.Path, err)
	}
	defer f.Close()

	fp, err := FingerprintOpenFile(f)
	if err != nil {
		return false, fmt.Errorf("dbpool: reload %s: fingerprint: %w", odb.Path, err)
	}
	if odb.Fingerprint.Equal(fp) {
		return false, nil // unchanged (e.g. our own save)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("dbpool: reload %s: %w", odb.Path, err)
	}
	newUUID, newDB, err := decodeDatabase(f, odb.cred)
	if err != nil {
		return false, fmt.Errorf("dbpool: reload %s: keeping previous content: %w", odb.Path, err)
	}
	if newUUID != odb.UUID {
		return false, fmt.Errorf("dbpool: reload %s: file now holds a different database; keeping previous content", odb.Path)
	}

	security.Do(func() {
		wipeDatabaseContent(odb.Db)
	})
	odb.Db = newDB
	odb.Fingerprint = fp
	return true, nil
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
