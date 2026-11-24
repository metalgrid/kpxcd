//go:build linux

// Package dbusapi implements the org.keepassxc.Daemon DBus interface.
package dbusapi

import (
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
	"github.com/metalgrid/kpxcd/internal/secretservice"
	"github.com/metalgrid/kpxcd/internal/security"
	"github.com/metalgrid/kpxcd/internal/sshagent"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
	"golang.org/x/crypto/ssh"
)

// DaemonDBus implements the org.keepassxc.Daemon DBus interface.
type DaemonDBus struct {
	conn     *dbus.Conn
	config   *config.Config
	pool     *dbpool.DatabasePool
	fido2    *fido2.Fido2Service
	sshAgent *sshagent.AgentServer
}

// NewDaemonDBus creates a new DBus API handler.
func NewDaemonDBus(cfg *config.Config, pool *dbpool.DatabasePool, f2 *fido2.Fido2Service, sshAgent *sshagent.AgentServer) *DaemonDBus {
	return &DaemonDBus{
		config:   cfg,
		pool:     pool,
		fido2:    f2,
		sshAgent: sshAgent,
	}
}

// NewDaemonDBusWithConn creates a DBus API handler with an existing connection.
// Use this when sharing a bus connection with other DBus services (e.g. Secret Service).
func NewDaemonDBusWithConn(cfg *config.Config, pool *dbpool.DatabasePool, f2 *fido2.Fido2Service, sshAgent *sshagent.AgentServer, conn *dbus.Conn) *DaemonDBus {
	return &DaemonDBus{
		config:   cfg,
		pool:     pool,
		fido2:    f2,
		sshAgent: sshAgent,
		conn:     conn,
	}
}

// Export connects to the session bus (if not already connected) and exports
// the daemon interface.
func (d *DaemonDBus) Export() error {
	if d.conn == nil {
		conn, err := dbus.ConnectSessionBus()
		if err != nil {
			return fmt.Errorf("dbusapi: failed to connect to session bus: %w", err)
		}
		d.conn = conn
	}

	// Request the bus name.
	reply, err := d.conn.RequestName("org.keepassxc.Daemon",
		dbus.NameFlagDoNotQueue)
	if err != nil {
		d.conn.Close()
		return fmt.Errorf("dbusapi: failed to request bus name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		d.conn.Close()
		return fmt.Errorf("dbusapi: bus name already taken")
	}

	// Export both interfaces at the same path.
	path := dbus.ObjectPath("/org/keepassxc/Daemon")
	if err := d.conn.Export(d, path, "org.keepassxc.Daemon"); err != nil {
		d.conn.Close()
		return fmt.Errorf("dbusapi: failed to export object: %w", err)
	}
	if err := d.conn.Export(d, path, "org.freedesktop.DBus.Introspectable"); err != nil {
		slog.Warn("dbusapi: failed to export introspection", "error", err)
	}

	slog.Info("DBus API exported", "name", "org.keepassxc.Daemon")
	return nil
}

// Close releases the bus name and closes the connection.
func (d *DaemonDBus) Close() {
	if d.conn != nil {
		d.conn.ReleaseName("org.keepassxc.Daemon")
		d.conn.Close()
	}
}

// authorize verifies that the D-Bus caller is the same Unix user as the
// daemon. A nil connection with an empty sender is allowed for unit tests.
func (d *DaemonDBus) authorize(sender dbus.Sender) error {
	if d.conn == nil && sender == "" {
		return nil
	}
	if d.conn == nil {
		return fmt.Errorf("dbusapi: no D-Bus connection available")
	}

	bus := d.conn.Object("org.freedesktop.DBus", dbus.ObjectPath("/org/freedesktop/DBus"))
	var uid uint32
	if err := bus.Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid); err != nil {
		return fmt.Errorf("dbusapi: failed to resolve caller user: %w", err)
	}
	if uid != uint32(os.Getuid()) {
		slog.Warn("DBus API access denied: caller UID mismatch",
			"caller_uid", uid,
			"daemon_uid", os.Getuid(),
			"sender", string(sender))
		return fmt.Errorf("dbusapi: caller UID %d does not match daemon UID %d", uid, os.Getuid())
	}
	return nil
}

// Ping responds with "pong".
func (d *DaemonDBus) Ping() (string, *dbus.Error) {
	return "pong", nil
}

// Introspect returns the XML introspection data for the daemon object.
func (d *DaemonDBus) Introspect() (string, *dbus.Error) {
	node := &introspect.Node{
		Name: "/org/keepassxc/Daemon",
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{Name: "org.keepassxc.Daemon", Methods: introspect.Methods(d)},
		},
	}
	return string(introspect.NewIntrospectable(node)), nil
}

// ListDatabases returns all known databases.
func (d *DaemonDBus) ListDatabases(sender dbus.Sender) ([]map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	dbs := d.pool.List()
	result := make([]map[string]dbus.Variant, len(dbs))

	for i, db := range dbs {
		result[i] = map[string]dbus.Variant{
			"uuid":        dbus.MakeVariant(db.UUID),
			"name":        dbus.MakeVariant(db.Name),
			"path":        dbus.MakeVariant(db.Path),
			"locked":      dbus.MakeVariant(db.IsLocked()),
			"auto_unlock": dbus.MakeVariant(false), // TODO: from config
		}
	}

	return result, nil
}

// UnlockDatabase unlocks a database by path.
func (d *DaemonDBus) UnlockDatabase(sender dbus.Sender, path string, credentialType string, credential dbus.Variant) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	var cred dbpool.Credential

	switch credentialType {
	case "password":
		pw, ok := credential.Value().(string)
		if !ok {
			return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: invalid password credential"))
		}
		ss, err := security.NewSecureString(pw)
		if err != nil {
			return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to create secure string: %w", err))
		}
		defer ss.Destroy()
		cred = dbpool.PasswordCredential(ss)

	case "keyfile":
		keyPath, ok := credential.Value().(string)
		if !ok {
			return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: invalid keyfile credential"))
		}
		cred = dbpool.KeyfileCredential(keyPath)

	case "none":
		cred = dbpool.Credential{Kind: dbpool.CredentialNone}

	default:
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: unsupported credential type: %s", credentialType))
	}

	uuid, err := d.pool.Open(path, cred)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to unlock database: %w", err))
	}

	slog.Info("DBus: database unlocked", "uuid", uuid, "path", path, "sender", string(sender))
	return true, nil
}

// LockDatabase locks a database by UUID.
func (d *DaemonDBus) LockDatabase(sender dbus.Sender, uuid string) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	if err := d.pool.Lock(uuid); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to lock database: %w", err))
	}
	slog.Info("DBus: database locked", "uuid", uuid, "sender", string(sender))
	return true, nil
}

// LockAll locks all databases.
func (d *DaemonDBus) LockAll(sender dbus.Sender) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	if err := d.pool.LockAll(); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to lock databases: %w", err))
	}
	slog.Info("DBus: all databases locked", "sender", string(sender))
	return true, nil
}

// GetEntry retrieves entry fields by database UUID and entry path.
// Passwords are intentionally not returned here; use the Secret Service
// path for encrypted secret retrieval.
func (d *DaemonDBus) GetEntry(sender dbus.Sender, uuid string, entryPath string) (map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	db, err := d.pool.Get(uuid)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
	}
	db.RLock()
	if db.Locked {
		db.RUnlock()
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: database is locked"))
	}
	// Search for the entry and copy out its fields while holding the read
	// lock: the entry's Values slice shares backing with the live database.
	entry := findEntryByPathLocked(db, entryPath)
	if entry == nil {
		db.RUnlock()
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: entry not found: %s", entryPath))
	}
	result := map[string]dbus.Variant{
		"title":    dbus.MakeVariant(entry.GetTitle()),
		"username": dbus.MakeVariant(entry.GetContent("UserName")),
		"url":      dbus.MakeVariant(entry.GetContent("URL")),
		"uuid":     dbus.MakeVariant(string(entry.UUID[:])),
	}
	db.RUnlock()

	return result, nil
}

// SearchEntries searches entries by query.
func (d *DaemonDBus) SearchEntries(sender dbus.Sender, uuid string, query string) ([]map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	if strings.TrimSpace(query) == "" {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: search query must not be empty"))
	}
	var dbs []*dbpool.OpenDatabase
	if uuid != "" {
		db, err := d.pool.Get(uuid)
		if err != nil {
			return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
		}
		dbs = []*dbpool.OpenDatabase{db}
	} else {
		dbs = d.pool.List()
	}

	var results []map[string]dbus.Variant
	for _, db := range dbs {
		db.RLock()
		if db.Locked {
			db.RUnlock()
			continue
		}
		entries := db.RootEntriesLocked()
		for i := range entries {
			e := &entries[i]
			if matchesQuery(e, query) {
				results = append(results, map[string]dbus.Variant{
					"title":    dbus.MakeVariant(e.GetTitle()),
					"username": dbus.MakeVariant(e.GetContent("UserName")),
					"url":      dbus.MakeVariant(e.GetContent("URL")),
					"uuid":     dbus.MakeVariant(string(e.UUID[:])),
					"dbuuid":   dbus.MakeVariant(db.UUID),
				})
			}
		}
		db.RUnlock()
	}

	return results, nil
}

// GetTotp returns the current TOTP code for an entry.
func (d *DaemonDBus) GetTotp(sender dbus.Sender, uuid string, entryPath string) (string, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	// TODO: Implement TOTP using github.com/pquerna/otp
	return "", dbus.MakeFailedError(fmt.Errorf("dbusapi: not yet implemented"))
}

// GeneratePassword generates a random password.
func (d *DaemonDBus) GeneratePassword(sender dbus.Sender, length int, charset string) (string, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	// TODO: Implement password generation
	return "", dbus.MakeFailedError(fmt.Errorf("dbusapi: not yet implemented"))
}

// GeneratePassphrase generates a diceware passphrase.
func (d *DaemonDBus) GeneratePassphrase(sender dbus.Sender, wordCount int, separator string) (string, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	// TODO: Implement passphrase generation
	return "", dbus.MakeFailedError(fmt.Errorf("dbusapi: not yet implemented"))
}

// SshListKeys lists SSH keys loaded in the agent. If uuid is non-empty,
// only keys from that database are returned.
func (d *DaemonDBus) SshListKeys(sender dbus.Sender, uuid string) ([]map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	if d.sshAgent == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: ssh agent is not running in agent mode"))
	}

	keys := d.sshAgent.Manager().ListIdentities()
	var result []map[string]dbus.Variant
	for _, lk := range keys {
		if uuid != "" && lk.DBUUID != uuid {
			continue
		}
		result = append(result, map[string]dbus.Variant{
			"fingerprint": dbus.MakeVariant(lk.Key.Fingerprint()),
			"comment":     dbus.MakeVariant(lk.Key.Comment),
			"type":        dbus.MakeVariant(lk.Key.Format),
			"entry_path":  dbus.MakeVariant(lk.Key.EntryUUID()),
			"db_uuid":     dbus.MakeVariant(lk.DBUUID),
		})
	}
	return result, nil
}

// SshAddKey extracts an SSH key from a database entry and adds it to the agent.
func (d *DaemonDBus) SshAddKey(sender dbus.Sender, uuid string, entryPath string, lifetime uint32, confirm bool) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	if d.sshAgent == nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: ssh agent is not running in agent mode"))
	}

	db, err := d.pool.Get(uuid)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
	}
	db.RLock()
	if db.Locked {
		db.RUnlock()
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database is locked"))
	}
	entry, lerr := lookupEntry(db.Db, entryPath)
	if lerr != nil {
		db.RUnlock()
		return false, dbus.MakeFailedError(lerr)
	}
	// Extract and publish while holding the read lock: the entry points into
	// database content, and AddIdentity must not land after a concurrent
	// database lock finished its removal. The manager never calls back into
	// the pool, so holding db.RLock across it cannot deadlock.
	key, err := sshagent.ExtractKeyFromEntry(entry, db.Db)
	if err != nil {
		db.RUnlock()
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to extract key: %w", err))
	}
	if key == nil {
		db.RUnlock()
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: entry does not contain an SSH key"))
	}
	key.SetDBUUID(db.UUID)

	if err := d.sshAgent.Manager().AddIdentity(key, lifetime, confirm, d.config.SSHAgent.RemoveOnLock, db.UUID, key.EntryUUID()); err != nil {
		db.RUnlock()
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to add key to agent: %w", err))
	}
	fingerprint := key.Fingerprint()
	dbName := db.Name
	db.RUnlock()
	slog.Info("DBus: SSH key added", "fingerprint", fingerprint, "db", dbName, "entry", entryPath)
	return true, nil
}

// SshScanDatabase scans an unlocked database for entries that contain SSH keys.
// If uuid is empty, all unlocked databases are scanned.
func (d *DaemonDBus) SshScanDatabase(sender dbus.Sender, uuid string) ([]map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	var dbs []*dbpool.OpenDatabase
	if uuid != "" {
		db, err := d.pool.Get(uuid)
		if err != nil {
			return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
		}
		dbs = []*dbpool.OpenDatabase{db}
	} else {
		dbs = d.pool.List()
	}

	var results []map[string]dbus.Variant
	for _, db := range dbs {
		db.RLock()
		if db.Locked {
			db.RUnlock()
			continue
		}
		for _, sk := range sshagent.ScanKeys(db.Db) {
			results = append(results, map[string]dbus.Variant{
				"title":       dbus.MakeVariant(sk.Title),
				"uuid":        dbus.MakeVariant(sk.EntryUUID),
				"type":        dbus.MakeVariant(sk.Key.Format),
				"fingerprint": dbus.MakeVariant(sk.Key.Fingerprint()),
				"attachment":  dbus.MakeVariant(sk.Attachment),
				"source":      dbus.MakeVariant(sk.Source),
				"autoload":    dbus.MakeVariant(sk.AutoLoad),
				"denied":      dbus.MakeVariant(sk.Denied),
				"db_uuid":     dbus.MakeVariant(db.UUID),
				"db_name":     dbus.MakeVariant(db.Name),
			})
		}
		db.RUnlock()
	}
	return results, nil
}

// SshGenerateKey generates a new SSH key pair, stores it as an attachment in
// the specified database entry, and writes both the kpxcd marker and real
// KeeAgent.settings so shared vaults also work in KeePassXC's agent.
func (d *DaemonDBus) SshGenerateKey(sender dbus.Sender, uuid string, entryPath string, keyType string, bits uint32, comment string) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	db, err := d.pool.Get(uuid)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
	}
	if db.IsLocked() {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database is locked"))
	}

	key, pemBytes, err := sshagent.GenerateSSHKeyPair(keyType, int(bits), comment)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: key generation failed: %w", err))
	}
	if comment != "" {
		key.SetComment(comment)
	}

	if err := db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		entry, err := findOrCreateEntry(kdb, entryPath)
		if err != nil {
			return err
		}
		return attachSSHKey(kdb, entry, pemBytes)
	}); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to save database: %w", err))
	}

	slog.Info("DBus: SSH key generated", "type", keyType, "db", db.Name, "entry", entryPath, "fingerprint", key.Fingerprint())
	return true, nil
}

// SshImportKey imports an existing SSH private key into a database entry.
func (d *DaemonDBus) SshImportKey(sender dbus.Sender, uuid string, entryPath string, keyData []byte, passphrase string) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	db, err := d.pool.Get(uuid)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
	}
	if db.IsLocked() {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database is locked"))
	}

	key, err := sshagent.ParsePrivateKey(keyData, passphrase)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to parse key: %w", err))
	}
	// ParsePrivateKey does not extract the OpenSSH comment; use the entry title.
	if key.Comment == "" {
		key.SetComment(entryPath)
	}
	// Store the key unencrypted (protected at rest by the KDBX encryption):
	// the agent resolves keys with the entry password or none, so persisting
	// the original passphrase-protected bytes would make the key unusable
	// after the next unlock.
	plainBlock, err := ssh.MarshalPrivateKey(key.PrivateKey, key.Comment)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to re-encode key: %w", err))
	}
	pemBytes := pem.EncodeToMemory(plainBlock)

	if err := db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		entry, err := findOrCreateEntry(kdb, entryPath)
		if err != nil {
			return err
		}
		return attachSSHKey(kdb, entry, pemBytes)
	}); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to save database: %w", err))
	}

	slog.Info("DBus: SSH key imported", "db", db.Name, "entry", entryPath, "fingerprint", key.Fingerprint())
	return true, nil
}

// lookupEntry finds one entry by hex UUID (exact, wins) or by exact title,
// skipping the recycle bin. More than one title match is an error.
func lookupEntry(kdb *gokeepasslib.Database, ref string) (*gokeepasslib.Entry, error) {
	if kdb == nil || kdb.Content == nil || kdb.Content.Root == nil {
		return nil, fmt.Errorf("dbusapi: database has no root group")
	}
	recycleBinUUID := dbpool.RecycleBinUUIDForDB(kdb)
	var byUUID, byTitle *gokeepasslib.Entry
	count := 0
	var visit func(groups []gokeepasslib.Group)
	visit = func(groups []gokeepasslib.Group) {
		for gi := range groups {
			g := &groups[gi]
			if dbpool.IsRecycled(g, recycleBinUUID) {
				continue
			}
			for ei := range g.Entries {
				e := &g.Entries[ei]
				if fmt.Sprintf("%x", e.UUID[:]) == ref && byUUID == nil {
					byUUID = e
				}
				if e.GetTitle() == ref {
					byTitle = e
					count++
				}
			}
			visit(g.Groups)
		}
	}
	visit(kdb.Content.Root.Groups)
	if byUUID != nil {
		return byUUID, nil
	}
	if count > 1 {
		return nil, fmt.Errorf("dbusapi: entry reference %q matches %d titles; use the entry UUID", ref, count)
	}
	if byTitle != nil {
		return byTitle, nil
	}
	return nil, fmt.Errorf("%w: %s", errEntryNotFound, ref)
}

// findOrCreateEntry finds an entry by title (via lookupEntry) or creates it
// in the root group.
func findOrCreateEntry(kdb *gokeepasslib.Database, title string) (*gokeepasslib.Entry, error) {
	if kdb.Content == nil || kdb.Content.Root == nil || len(kdb.Content.Root.Groups) == 0 {
		return nil, fmt.Errorf("dbusapi: database has no root group")
	}
	if entry, err := lookupEntry(kdb, title); err == nil {
		return entry, nil
	} else if !errors.Is(err, errEntryNotFound) {
		return nil, err
	}
	group := &kdb.Content.Root.Groups[0]
	newEntry := gokeepasslib.NewEntry()
	newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{
		Key:   "Title",
		Value: gokeepasslib.V{Content: title},
	})
	group.Entries = append(group.Entries, newEntry)
	return &group.Entries[len(group.Entries)-1], nil
}

// govern is the pure load of an entry's SSH governance: settings attachment,
// else legacy custom data, else defaults. No writes.
type govern struct {
	s          sshagent.EntrySettings
	exists     bool // any metadata present (attachment or legacy)
	denied     bool
	unreadable bool // settings attachment present but unparseable
	file       bool // file-based location
}

func defaultSettings() sshagent.EntrySettings {
	return sshagent.EntrySettings{
		AllowUseOfSshKey:           true,
		AddAtDatabaseOpen:          true,
		RemoveAtDatabaseClose:      true,
		LifetimeConstraintDuration: 600, // KeePassXC's default
		Location:                   sshagent.EntryLocation{SelectedType: "attachment", AttachmentName: "ssh-key"},
	}
}

func loadGovern(kdb *gokeepasslib.Database, entry *gokeepasslib.Entry) govern {
	s, err := existingEntrySettings(kdb, entry)
	switch {
	case err != nil:
		// Present but unreadable: fail closed, counts as denied for writes.
		return govern{s: defaultSettings(), exists: true, denied: true, unreadable: true}
	case s != nil:
		return govern{
			s:      *s,
			exists: true,
			denied: !s.AllowUseOfSshKey,
			file:   s.AllowUseOfSshKey && s.Location.SelectedType == "file",
		}
	}
	if l := legacyKeeAgent(entry); l != nil {
		s := defaultSettings()
		s.AllowUseOfSshKey = l.allow
		s.AddAtDatabaseOpen = l.autoload
		s.Location.AttachmentName = l.attachment
		s.Location.SelectedType = l.selectedType
		return govern{s: s, exists: true, denied: !l.allow, file: l.selectedType == "file"}
	}
	return govern{s: defaultSettings()}
}

// applyGovern cannot fail (xml is already marshaled). marker "" removes the
// kpxcd marker. Writes the settings attachment and drops legacy custom data.
func applyGovern(kdb *gokeepasslib.Database, entry *gokeepasslib.Entry, xml []byte, marker string) {
	bin := kdb.AddBinary(xml)
	ref := bin.CreateReference(sshagent.KeeAgentSettingsAttachment)
	found := false
	for i := range entry.Binaries {
		if strings.EqualFold(entry.Binaries[i].Name, sshagent.KeeAgentSettingsAttachment) {
			entry.Binaries[i] = ref
			found = true
			break
		}
	}
	if !found {
		entry.Binaries = append(entry.Binaries, ref)
	}
	if marker == "" {
		if idx := entry.GetIndex(sshagent.MarkerSSHKey); idx >= 0 {
			entry.Values = append(entry.Values[:idx], entry.Values[idx+1:]...)
		}
	} else {
		setEntryValue(entry, sshagent.MarkerSSHKey, marker, false)
	}
	for i := range entry.CustomData {
		if strings.EqualFold(entry.CustomData[i].Key, sshagent.KeeAgentSettingsAttachment) {
			entry.CustomData = append(entry.CustomData[:i], entry.CustomData[i+1:]...)
			break
		}
	}
}

// attachSSHKey stores pemBytes as the entry's "ssh-key" attachment and writes
// both governance markers. All checks run before any write. Refuses denied or
// unreadable entries, and refuses to replace an existing key that is
// unparseable or has a different fingerprint (fail closed).
func attachSSHKey(kdb *gokeepasslib.Database, entry *gokeepasslib.Entry, pemBytes []byte) error {
	g := loadGovern(kdb, entry)
	if g.unreadable {
		return fmt.Errorf("dbusapi: KeeAgent.settings unreadable; refusing to touch the entry")
	}
	if g.denied {
		return fmt.Errorf("dbusapi: KeeAgent settings deny this entry; not overwriting the key")
	}
	if g.file {
		return fmt.Errorf("dbusapi: file-based SSH key locations are not supported")
	}
	newKey, err := sshagent.ParsePrivateKey(pemBytes, "")
	if err != nil {
		return fmt.Errorf("dbusapi: new key does not parse: %w", err)
	}
	for _, ref := range entry.Binaries {
		if strings.EqualFold(ref.Name, sshagent.KeeAgentSettingsAttachment) {
			continue
		}
		binary := kdb.FindBinary(ref.Value.ID)
		if binary == nil {
			continue
		}
		old, err := binary.GetContentBytes()
		if err != nil {
			return fmt.Errorf("dbusapi: decode existing attachment %q: %w", ref.Name, err)
		}
		existing, perr := sshagent.ParsePrivateKey(old, entry.GetPassword())
		if perr != nil {
			existing, perr = sshagent.ParsePrivateKey(old, "")
		}
		if perr != nil {
			// Fail closed for the key-named attachment; other attachments
			// that do not parse are simply not keys.
			if strings.EqualFold(ref.Name, "ssh-key") {
				return fmt.Errorf("dbusapi: existing ssh-key attachment does not parse; refusing to overwrite")
			}
			continue
		}
		if existing.Fingerprint() != newKey.Fingerprint() {
			return fmt.Errorf("dbusapi: entry already has a different SSH key in attachment %q (%s); refusing to overwrite", ref.Name, existing.Fingerprint())
		}
	}

	// All checks passed; mutate now.
	g.s.AllowUseOfSshKey = true
	g.s.AddAtDatabaseOpen = true
	g.s.Location = sshagent.EntryLocation{SelectedType: "attachment", AttachmentName: "ssh-key"}
	xmlBytes, err := sshagent.MarshalEntrySettings(&g.s)
	if err != nil {
		return err
	}
	binary := kdb.AddBinary(pemBytes)
	ref := binary.CreateReference("ssh-key")
	found := false
	for i := range entry.Binaries {
		if strings.EqualFold(entry.Binaries[i].Name, "ssh-key") {
			entry.Binaries[i] = ref
			found = true
			break
		}
	}
	if !found {
		entry.Binaries = append(entry.Binaries, ref)
	}
	applyGovern(kdb, entry, xmlBytes, "ssh-key")
	return nil
}

// existingEntrySettings parses the entry's current KeeAgent.settings
// attachment, if any.
// existingEntrySettings returns the entry's KeeAgent.settings attachment.
// A present-but-unreadable attachment is an error, not nil: nil would make
// callers treat a possible deny as absent (fail open).
func existingEntrySettings(kdb *gokeepasslib.Database, entry *gokeepasslib.Entry) (*sshagent.EntrySettings, error) {
	for _, ref := range entry.Binaries {
		if !strings.EqualFold(ref.Name, sshagent.KeeAgentSettingsAttachment) {
			continue
		}
		binary := kdb.FindBinary(ref.Value.ID)
		if binary == nil {
			return nil, fmt.Errorf("dbusapi: KeeAgent.settings attachment not found in database")
		}
		content, err := binary.GetContentBytes()
		if err != nil {
			return nil, fmt.Errorf("dbusapi: decode KeeAgent.settings: %w", err)
		}
		s, err := sshagent.ParseEntrySettings(content)
		if err != nil {
			return nil, fmt.Errorf("dbusapi: KeeAgent.settings unreadable: %w", err)
		}
		return s, nil
	}
	return nil, nil
}

// errEntryNotFound is the sentinel lookupEntry returns for a missing entry.
var errEntryNotFound = fmt.Errorf("dbusapi: entry not found")

// setEntryValue sets an entry value field, replacing an existing one.
func setEntryValue(entry *gokeepasslib.Entry, key, value string, protected bool) {
	idx := entry.GetIndex(key)
	v := gokeepasslib.ValueData{
		Key: key,
		Value: gokeepasslib.V{
			Content:   value,
			Protected: wrappers.BoolWrapper{Bool: protected},
		},
	}
	if idx >= 0 {
		entry.Values[idx] = v
		return
	}
	entry.Values = append(entry.Values, v)
}

// SshRemoveKey removes an SSH key from the agent by fingerprint.
func (d *DaemonDBus) SshRemoveKey(sender dbus.Sender, fingerprint string) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	if d.sshAgent == nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: ssh agent is not running in agent mode"))
	}

	if err := d.sshAgent.Manager().RemoveIdentity(fingerprint); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to remove key: %w", err))
	}
	slog.Info("DBus: SSH key removed", "fingerprint", fingerprint)
	return true, nil
}

// ActionSSExport is the polkit action gating private-key export.
const ActionSSHExport = "org.keepassxc.daemon.ssh.export"

// SshExportKey exports one stored SSH private key as OpenSSH PEM. Gated by
// polkit auth_self per call: any same-user process could otherwise call this
// without the user approving. Key bytes cross the session bus; the CLI
// re-encrypts them with a passphrase by default. Logs fingerprint and
// caller, never key material.
func (d *DaemonDBus) SshExportKey(sender dbus.Sender, uuid string, entryRef string) ([]byte, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	if err := d.authorizeAction(sender, ActionSSHExport); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	db, err := d.pool.Get(uuid)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
	}
	db.RLock()
	if db.Locked {
		db.RUnlock()
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: database is locked"))
	}
	entry, lerr := lookupEntry(db.Db, entryRef)
	var key *sshagent.Key
	if lerr == nil {
		// P5: export ignores the agent-use deny (export itself is polkit-gated).
		key, err = sshagent.ExtractKeyForExport(entry, db.Db)
	}
	db.RUnlock()
	if lerr != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: entry not found: %s", entryRef))
	}
	if key == nil || err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: no loadable SSH key for entry %s", entryRef))
	}
	if key.PrivateKey == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: key has no private material (encrypted key without passphrase)"))
	}
	var pemBytes []byte
	security.Do(func() {
		block, merr := ssh.MarshalPrivateKey(key.PrivateKey, "")
		if merr != nil {
			err = merr
			return
		}
		pemBytes = pem.EncodeToMemory(block)
	})
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: marshal key: %w", err))
	}
	slog.Info("DBus: SSH key exported", "fingerprint", key.Fingerprint(), "db", db.Name, "entry", entryRef, "sender", string(sender))
	return pemBytes, nil
}

// SshSetAutoload sets or clears an entry's auto-load marker. All checks run
// before any write. On: deny/unreadable need overrideDeny, file-type refused.
// Off: never changes Allow; unreadable settings are an error (nothing
// auto-loads anyway); legacy entries are migrated to real settings.
func (d *DaemonDBus) SshSetAutoload(sender dbus.Sender, uuid string, entryRef string, on bool, overrideDeny bool) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	db, err := d.pool.Get(uuid)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database not found: %w", err))
	}
	if db.IsLocked() {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: database is locked"))
	}

	if err := db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		entry, err := lookupEntry(kdb, entryRef)
		if err != nil {
			return err
		}
		g := loadGovern(kdb, entry)
		if on {
			if (g.unreadable || g.denied) && !overrideDeny {
				return fmt.Errorf("dbusapi: entry is denied or has unreadable KeeAgent settings; pass overrideDeny to override")
			}
			if g.file {
				return fmt.Errorf("dbusapi: file-based SSH key locations are not supported")
			}
			name, err := sshagent.ChooseKeyAttachment(entry, kdb)
			if err != nil {
				return err
			}
			if err := sshagent.VerifyKeyAttachment(entry, kdb, name); err != nil {
				return fmt.Errorf("dbusapi: chosen key does not load: %w", err)
			}
			g.s.AllowUseOfSshKey = true
			g.s.AddAtDatabaseOpen = true
			g.s.Location = sshagent.EntryLocation{SelectedType: "attachment", AttachmentName: name}
			xmlBytes, err := sshagent.MarshalEntrySettings(&g.s)
			if err != nil {
				return err
			}
			applyGovern(kdb, entry, xmlBytes, name)
			return nil
		}
		// OFF
		if g.unreadable {
			return fmt.Errorf("dbusapi: KeeAgent.settings unreadable; nothing auto-loads from this entry anyway")
		}
		if g.file || !g.exists {
			// kpxcd never loads these; just remove the marker if present.
			if idx := entry.GetIndex(sshagent.MarkerSSHKey); idx >= 0 {
				entry.Values = append(entry.Values[:idx], entry.Values[idx+1:]...)
			}
			return nil
		}
		g.s.AddAtDatabaseOpen = false // Allow untouched
		xmlBytes, err := sshagent.MarshalEntrySettings(&g.s)
		if err != nil {
			return err
		}
		applyGovern(kdb, entry, xmlBytes, "")
		return nil
	}); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: failed to save database: %w", err))
	}
	slog.Info("DBus: SSH autoload changed", "db", db.Name, "entry", entryRef, "on", on)
	return true, nil
}

// legacyKeeAgent reads the old <KeeAgent> custom-data form, if present.
func legacyKeeAgent(entry *gokeepasslib.Entry) *struct {
	allow        bool
	autoload     bool
	attachment   string
	selectedType string
} {
	for _, cd := range entry.CustomData {
		if !strings.EqualFold(cd.Key, sshagent.KeeAgentSettingsAttachment) {
			continue
		}
		var l struct {
			Allow      bool   `xml:"allowUseOfSshKey"`
			Autoload   bool   `xml:"addAtDatabaseOpen"`
			Attachment string `xml:"location>attachment"`
			SelType    string `xml:"location>selectedType"`
		}
		if err := xml.Unmarshal([]byte(cd.Value), &l); err == nil {
			return &struct {
				allow        bool
				autoload     bool
				attachment   string
				selectedType string
			}{allow: l.Allow, autoload: l.Autoload, attachment: l.Attachment, selectedType: l.SelType}
		}
	}
	return nil
}

// polkit action IDs for passkey operations (contrib/polkit policy).
const (
	ActionPasskeyCreate = "org.keepassxc.daemon.passkey.create"
	ActionPasskeyAssert = "org.keepassxc.daemon.passkey.assert"
)

// authorizeAction authorizes the sender and gates the operation behind
// polkit (auth_self; the desktop agent prompts). Unit-test-style calls
// (empty sender, no connection) follow the same convention as authorize:
// real D-Bus callers always carry a sender, so no production path skips
// the gate.
func (d *DaemonDBus) authorizeAction(sender dbus.Sender, actionID string) error {
	if err := d.authorize(sender); err != nil {
		return err
	}
	if d.conn == nil && sender == "" {
		return nil
	}

	bus := d.conn.Object("org.freedesktop.DBus", dbus.ObjectPath("/org/freedesktop/DBus"))
	var pid uint32
	if err := bus.Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, string(sender)).Store(&pid); err != nil {
		return fmt.Errorf("dbusapi: failed to resolve caller process: %w", err)
	}
	var uid uint32
	if err := bus.Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid); err != nil {
		return fmt.Errorf("dbusapi: failed to resolve caller user: %w", err)
	}

	caller := secretservice.CallerInfo{PID: pid, UID: uid, Sender: string(sender)}
	if err := secretservice.CheckPolkitAuthorization(caller, actionID); err != nil {
		slog.Warn("passkey operation refused by presence gate", "action", actionID, "sender", string(sender), "err", err)
		return fmt.Errorf("dbusapi: presence gate refused the operation")
	}
	return nil
}

// CreatePasskey creates and persists a passkey for the given relying party.
func (d *DaemonDBus) CreatePasskey(sender dbus.Sender, uuid string, rpID string, rpName string, userName string, userDisplayName string, algorithms []int) (map[string]dbus.Variant, *dbus.Error) {
	if d.fido2 == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: fido2 service is not running"))
	}
	if err := d.authorizeAction(sender, ActionPasskeyCreate); err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	entry, err := d.fido2.CreatePasskey(uuid, rpID, rpName, userName, userDisplayName, algorithms)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: %w", err))
	}
	return map[string]dbus.Variant{
		"rpID":         dbus.MakeVariant(entry.RPID),
		"rpName":       dbus.MakeVariant(entry.RPName),
		"username":     dbus.MakeVariant(entry.Username),
		"credentialID": dbus.MakeVariant(entry.CredentialID),
		"userHandle":   dbus.MakeVariant(entry.UserHandle),
	}, nil
}

// AssertPasskey signs one assertion for a stored passkey. The caller
// supplies the client data hash; user presence is established by the
// polkit gate inside this call.
func (d *DaemonDBus) AssertPasskey(sender dbus.Sender, rpID string, credentialID string, clientDataHash []byte) (map[string]dbus.Variant, *dbus.Error) {
	if d.fido2 == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: fido2 service is not running"))
	}
	if err := d.authorizeAction(sender, ActionPasskeyAssert); err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	result, err := d.fido2.SignAssertion(fido2.SignAssertionInput{
		RPID:           rpID,
		CredentialID:   credentialID,
		ClientDataHash: clientDataHash,
		UserPresent:    true, // gate approved above
	})
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: %w", err))
	}
	return map[string]dbus.Variant{
		"credentialID":      dbus.MakeVariant(result.CredentialID),
		"userHandle":        dbus.MakeVariant(result.UserHandle),
		"authenticatorData": dbus.MakeVariant(result.AuthenticatorData),
		"signature":         dbus.MakeVariant(result.Signature),
		"signCount":         dbus.MakeVariant(result.SignCount),
	}, nil
}

// ListPasskeys returns metadata for every stored passkey. Credential IDs
// and relying parties are not secret material; private keys never leave
// the database.
func (d *DaemonDBus) ListPasskeys(sender dbus.Sender) ([]map[string]dbus.Variant, *dbus.Error) {
	if d.fido2 == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: fido2 service is not running"))
	}
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	results := []map[string]dbus.Variant{}
	for _, db := range d.pool.List() {
		found, err := d.fido2.FindPasskeysByRPID(db.UUID, "")
		if err != nil {
			return nil, dbus.MakeFailedError(fmt.Errorf("dbusapi: %w", err))
		}
		for _, pk := range found {
			results = append(results, map[string]dbus.Variant{
				"database":     dbus.MakeVariant(db.Name),
				"rpID":         dbus.MakeVariant(pk.RPID),
				"rpName":       dbus.MakeVariant(pk.RPName),
				"username":     dbus.MakeVariant(pk.Username),
				"credentialID": dbus.MakeVariant(pk.CredentialID),
				"signCount":    dbus.MakeVariant(pk.SignCount),
			})
		}
	}
	return results, nil
}

// RemovePasskey deletes the passkey with the given credential ID.
func (d *DaemonDBus) RemovePasskey(sender dbus.Sender, credentialID string) (bool, *dbus.Error) {
	if d.fido2 == nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: fido2 service is not running"))
	}
	if err := d.authorizeAction(sender, ActionPasskeyCreate); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	if err := d.fido2.RemovePasskey(credentialID); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: %w", err))
	}
	return true, nil
}

// ImportPasskey stores one externally exported credential (Bitwarden
// format: PKCS#8 ECDSA P-256). Caller passes one credential at a time.
func (d *DaemonDBus) ImportPasskey(sender dbus.Sender, uuid string, rpID string, rpName string, username string, userDisplayName string, credentialID string, userHandle string, privateKeyPEM string, signCount int32) (bool, *dbus.Error) {
	if d.fido2 == nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: fido2 service is not running"))
	}
	if err := d.authorizeAction(sender, ActionPasskeyCreate); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	_, err := d.fido2.ImportPasskey(uuid, fido2.ImportPasskeyInput{
		RPID:            rpID,
		RPName:          rpName,
		Username:        username,
		UserDisplayName: userDisplayName,
		CredentialID:    credentialID,
		UserHandle:      userHandle,
		PrivateKeyPEM:   privateKeyPEM,
		SignCount:       uint32(signCount),
	})
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("dbusapi: %w", err))
	}
	return true, nil
}

// findEntryByPathLocked is findEntryByPath without taking the database lock:
// the caller must already hold RLock or Lock on db.
func findEntryByPathLocked(db *dbpool.OpenDatabase, path string) *gokeepasslib.Entry {
	entries := db.RootEntriesLocked()
	for i := range entries {
		if entries[i].GetTitle() == path || entries[i].GetContent("UserName") == path {
			return &entries[i]
		}
	}
	return nil
}

// matchesQuery checks if an entry matches a search query.
func matchesQuery(entry *gokeepasslib.Entry, query string) bool {
	q := strings.ToLower(query)
	return strings.Contains(strings.ToLower(entry.GetTitle()), q) ||
		strings.Contains(strings.ToLower(entry.GetContent("UserName")), q) ||
		strings.Contains(strings.ToLower(entry.GetContent("URL")), q)
}
