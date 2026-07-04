//go:build linux

// Package dbusapi implements the org.keepassxc.Daemon DBus interface.
package dbusapi

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/fido2"
	"github.com/metalgrid/kpxcd/internal/security"
	"github.com/metalgrid/kpxcd/internal/sshagent"
	"github.com/tobischo/gokeepasslib/v3"
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
		return fmt.Errorf("no D-Bus connection available")
	}

	bus := d.conn.Object("org.freedesktop.DBus", dbus.ObjectPath("/org/freedesktop/DBus"))
	var uid uint32
	if err := bus.Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid); err != nil {
		return fmt.Errorf("failed to resolve caller user: %w", err)
	}
	if uid != uint32(os.Getuid()) {
		slog.Warn("DBus API access denied: caller UID mismatch",
			"caller_uid", uid,
			"daemon_uid", os.Getuid(),
			"sender", string(sender))
		return fmt.Errorf("caller UID %d does not match daemon UID %d", uid, os.Getuid())
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
			"locked":      dbus.MakeVariant(db.Locked),
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
			return false, dbus.MakeFailedError(fmt.Errorf("invalid password credential"))
		}
		ss, err := security.NewSecureString(pw)
		if err != nil {
			return false, dbus.MakeFailedError(fmt.Errorf("failed to create secure string: %w", err))
		}
		defer ss.Destroy()
		cred = dbpool.PasswordCredential(ss)

	case "keyfile":
		keyPath, ok := credential.Value().(string)
		if !ok {
			return false, dbus.MakeFailedError(fmt.Errorf("invalid keyfile credential"))
		}
		cred = dbpool.KeyfileCredential(keyPath)

	case "none":
		cred = dbpool.Credential{Kind: dbpool.CredentialNone}

	default:
		return false, dbus.MakeFailedError(fmt.Errorf("unsupported credential type: %s", credentialType))
	}

	uuid, err := d.pool.Open(path, cred)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to unlock database: %w", err))
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
		return false, dbus.MakeFailedError(fmt.Errorf("failed to lock database: %w", err))
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
		return false, dbus.MakeFailedError(fmt.Errorf("failed to lock databases: %w", err))
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
		return nil, dbus.MakeFailedError(fmt.Errorf("database not found: %w", err))
	}
	db.RLock()
	locked := db.Locked
	db.RUnlock()
	if locked {
		return nil, dbus.MakeFailedError(fmt.Errorf("database is locked"))
	}

	// Search for the entry by path.
	entry := findEntryByPath(db, entryPath)
	if entry == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("entry not found: %s", entryPath))
	}

	result := map[string]dbus.Variant{
		"title":    dbus.MakeVariant(entry.GetTitle()),
		"username": dbus.MakeVariant(entry.GetContent("UserName")),
		"url":      dbus.MakeVariant(entry.GetContent("URL")),
		"uuid":     dbus.MakeVariant(string(entry.UUID[:])),
	}

	return result, nil
}

// SearchEntries searches entries by query.
func (d *DaemonDBus) SearchEntries(sender dbus.Sender, uuid string, query string) ([]map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	if strings.TrimSpace(query) == "" {
		return nil, dbus.MakeFailedError(fmt.Errorf("search query must not be empty"))
	}
	var dbs []*dbpool.OpenDatabase
	if uuid != "" {
		db, err := d.pool.Get(uuid)
		if err != nil {
			return nil, dbus.MakeFailedError(fmt.Errorf("database not found: %w", err))
		}
		dbs = []*dbpool.OpenDatabase{db}
	} else {
		dbs = d.pool.List()
	}

	var results []map[string]dbus.Variant
	for _, db := range dbs {
		db.RLock()
		locked := db.Locked
		db.RUnlock()
		if locked {
			continue
		}
		entries := db.RootEntries()
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
	}

	return results, nil
}

// GetTotp returns the current TOTP code for an entry.
func (d *DaemonDBus) GetTotp(sender dbus.Sender, uuid string, entryPath string) (string, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	// TODO: Implement TOTP using github.com/pquerna/otp
	return "", dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// GeneratePassword generates a random password.
func (d *DaemonDBus) GeneratePassword(sender dbus.Sender, length int, charset string) (string, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	// TODO: Implement password generation
	return "", dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// GeneratePassphrase generates a diceware passphrase.
func (d *DaemonDBus) GeneratePassphrase(sender dbus.Sender, wordCount int, separator string) (string, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	// TODO: Implement passphrase generation
	return "", dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// SshListKeys lists SSH keys loaded in the agent. If uuid is non-empty,
// only keys from that database are returned.
func (d *DaemonDBus) SshListKeys(sender dbus.Sender, uuid string) ([]map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	if d.sshAgent == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("SSH agent is not running in agent mode"))
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
		return false, dbus.MakeFailedError(fmt.Errorf("SSH agent is not running in agent mode"))
	}

	db, err := d.pool.Get(uuid)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("database not found: %w", err))
	}
	db.RLock()
	locked := db.Locked
	db.RUnlock()
	if locked {
		return false, dbus.MakeFailedError(fmt.Errorf("database is locked"))
	}

	db.RLock()
	entry := findEntryByPath(db, entryPath)
	db.RUnlock()
	if entry == nil {
		return false, dbus.MakeFailedError(fmt.Errorf("entry not found: %s", entryPath))
	}

	key, err := sshagent.ExtractKeyFromEntry(entry, db.Db)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to extract key: %w", err))
	}
	if key == nil {
		return false, dbus.MakeFailedError(fmt.Errorf("entry does not contain an SSH key"))
	}
	key.SetDBUUID(db.UUID)

	if err := d.sshAgent.Manager().AddIdentity(key, lifetime, confirm, d.config.SSHAgent.RemoveOnLock, db.UUID, key.EntryUUID()); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to add key to agent: %w", err))
	}
	slog.Info("DBus: SSH key added", "fingerprint", key.Fingerprint(), "db", db.Name, "entry", entryPath)
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
			return nil, dbus.MakeFailedError(fmt.Errorf("database not found: %w", err))
		}
		dbs = []*dbpool.OpenDatabase{db}
	} else {
		dbs = d.pool.List()
	}

	var results []map[string]dbus.Variant
	for _, db := range dbs {
		db.RLock()
		locked := db.Locked
		db.RUnlock()
		if locked {
			continue
		}
		db.RLock()
		entries := db.RootEntries()
		db.RUnlock()

		for i := range entries {
			key, err := sshagent.ExtractKeyFromEntry(&entries[i], db.Db)
			if err != nil || key == nil {
				continue
			}
			results = append(results, map[string]dbus.Variant{
				"title":       dbus.MakeVariant(entries[i].GetTitle()),
				"uuid":        dbus.MakeVariant(fmt.Sprintf("%x", entries[i].UUID[:])),
				"type":        dbus.MakeVariant(key.Format),
				"fingerprint": dbus.MakeVariant(key.Fingerprint()),
				"db_uuid":     dbus.MakeVariant(db.UUID),
				"db_name":     dbus.MakeVariant(db.Name),
			})
		}
	}
	return results, nil
}

// SshGenerateKey generates a new SSH key pair, stores it as an attachment in
// the specified database entry, and sets KeeAgent metadata.
func (d *DaemonDBus) SshGenerateKey(sender dbus.Sender, uuid string, entryPath string, keyType string, bits uint32, comment string) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	db, err := d.pool.Get(uuid)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("database not found: %w", err))
	}
	db.RLock()
	locked := db.Locked
	db.RUnlock()
	if locked {
		return false, dbus.MakeFailedError(fmt.Errorf("database is locked"))
	}

	key, pemBytes, err := sshagent.GenerateSSHKeyPair(keyType, int(bits))
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("key generation failed: %w", err))
	}
	if comment != "" {
		key.SetComment(comment)
	}

	if err := db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		if kdb.Content == nil || kdb.Content.Root == nil || len(kdb.Content.Root.Groups) == 0 {
			return fmt.Errorf("database has no root group")
		}

		// Find existing entry by title or create a new one in the root group.
		var entry *gokeepasslib.Entry
		var group *gokeepasslib.Group
		for gi := range kdb.Content.Root.Groups {
			g := &kdb.Content.Root.Groups[gi]
			for ei := range g.Entries {
				if g.Entries[ei].GetTitle() == entryPath {
					entry = &g.Entries[ei]
					group = g
					break
				}
			}
			if entry != nil {
				break
			}
		}
		if entry == nil {
			group = &kdb.Content.Root.Groups[0]
			newEntry := gokeepasslib.NewEntry()
			newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{
				Key:   "Title",
				Value: gokeepasslib.V{Content: entryPath},
			})
			group.Entries = append(group.Entries, newEntry)
			entry = &group.Entries[len(group.Entries)-1]
		}

		// Add private key as a binary attachment.
		binary := kdb.AddBinary(pemBytes)
		ref := binary.CreateReference("ssh-key")
		found := false
		for i := range entry.Binaries {
			if entry.Binaries[i].Name == "ssh-key" {
				entry.Binaries[i] = ref
				found = true
				break
			}
		}
		if !found {
			entry.Binaries = append(entry.Binaries, ref)
		}

		// Set KeeAgent settings.
		settings := sshagent.KeeAgentSettings{
			AllowUseOfSshKey:      true,
			AddAtDatabaseOpen:     true,
			RemoveAtDatabaseClose: true,
			Location: sshagent.Location{
				SelectedType: "attachment",
				Attachment:   "ssh-key",
			},
		}
		settingsXML, err := xml.Marshal(settings)
		if err != nil {
			return fmt.Errorf("marshal KeeAgent settings: %w", err)
		}
		cdFound := false
		for i := range entry.CustomData {
			if strings.EqualFold(entry.CustomData[i].Key, "KeeAgent.settings") {
				entry.CustomData[i].Value = string(settingsXML)
				cdFound = true
				break
			}
		}
		if !cdFound {
			entry.CustomData = append(entry.CustomData, gokeepasslib.CustomData{
				Key:   "KeeAgent.settings",
				Value: string(settingsXML),
			})
		}

		// Store comment in Notes if provided.
		if comment != "" {
			notesFound := false
			for i := range entry.Values {
				if entry.Values[i].Key == "Notes" {
					entry.Values[i].Value.Content = comment
					notesFound = true
					break
				}
			}
			if !notesFound {
				entry.Values = append(entry.Values, gokeepasslib.ValueData{
					Key:   "Notes",
					Value: gokeepasslib.V{Content: comment},
				})
			}
		}

		return nil
	}); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to save database: %w", err))
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
		return false, dbus.MakeFailedError(fmt.Errorf("database not found: %w", err))
	}
	db.RLock()
	locked := db.Locked
	db.RUnlock()
	if locked {
		return false, dbus.MakeFailedError(fmt.Errorf("database is locked"))
	}

	key, err := sshagent.ParsePrivateKey(keyData, passphrase)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to parse key: %w", err))
	}

	if err := db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		if kdb.Content == nil || kdb.Content.Root == nil || len(kdb.Content.Root.Groups) == 0 {
			return fmt.Errorf("database has no root group")
		}

		var entry *gokeepasslib.Entry
		for gi := range kdb.Content.Root.Groups {
			g := &kdb.Content.Root.Groups[gi]
			for ei := range g.Entries {
				if g.Entries[ei].GetTitle() == entryPath {
					entry = &g.Entries[ei]
					break
				}
			}
			if entry != nil {
				break
			}
		}
		if entry == nil {
			group := &kdb.Content.Root.Groups[0]
			newEntry := gokeepasslib.NewEntry()
			newEntry.Values = append(newEntry.Values, gokeepasslib.ValueData{
				Key:   "Title",
				Value: gokeepasslib.V{Content: entryPath},
			})
			group.Entries = append(group.Entries, newEntry)
			entry = &group.Entries[len(group.Entries)-1]
		}

		binary := kdb.AddBinary(keyData)
		ref := binary.CreateReference("ssh-key")
		found := false
		for i := range entry.Binaries {
			if entry.Binaries[i].Name == "ssh-key" {
				entry.Binaries[i] = ref
				found = true
				break
			}
		}
		if !found {
			entry.Binaries = append(entry.Binaries, ref)
		}

		settings := sshagent.KeeAgentSettings{
			AllowUseOfSshKey:      true,
			AddAtDatabaseOpen:     true,
			RemoveAtDatabaseClose: true,
			Location: sshagent.Location{
				SelectedType: "attachment",
				Attachment:   "ssh-key",
			},
		}
		settingsXML, err := xml.Marshal(settings)
		if err != nil {
			return fmt.Errorf("marshal KeeAgent settings: %w", err)
		}
		cdFound := false
		for i := range entry.CustomData {
			if strings.EqualFold(entry.CustomData[i].Key, "KeeAgent.settings") {
				entry.CustomData[i].Value = string(settingsXML)
				cdFound = true
				break
			}
		}
		if !cdFound {
			entry.CustomData = append(entry.CustomData, gokeepasslib.CustomData{
				Key:   "KeeAgent.settings",
				Value: string(settingsXML),
			})
		}

		return nil
	}); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to save database: %w", err))
	}

	slog.Info("DBus: SSH key imported", "db", db.Name, "entry", entryPath, "fingerprint", key.Fingerprint())
	return true, nil
}

// SshExportKey is intentionally disabled: kpxcd exposes SSH keys for signing,
// not private-key extraction.
func (d *DaemonDBus) SshExportKey(sender dbus.Sender, fingerprint string) ([]byte, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	return nil, dbus.MakeFailedError(fmt.Errorf("SSH private-key export is disabled"))
}

// SshTestSign signs test data with a loaded SSH key and returns the signature.
func (d *DaemonDBus) SshTestSign(sender dbus.Sender, fingerprint string, data []byte) ([]byte, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	if d.sshAgent == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("SSH agent is not running in agent mode"))
	}

	lk := d.sshAgent.Manager().FindIdentityByFingerprint(fingerprint)
	if lk == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("key not found: %s", fingerprint))
	}

	var sig *ssh.Signature
	var signErr error
	security.Do(func() {
		sig, signErr = lk.Key.Sign(data)
	})
	if signErr != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("sign failed: %w", signErr))
	}
	slog.Info("DBus: SSH test sign performed", "fingerprint", fingerprint, "sender", string(sender))
	return ssh.Marshal(sig), nil
}

// SshRemoveKey removes an SSH key from the agent by fingerprint.
func (d *DaemonDBus) SshRemoveKey(sender dbus.Sender, fingerprint string) (bool, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return false, dbus.MakeFailedError(err)
	}
	if d.sshAgent == nil {
		return false, dbus.MakeFailedError(fmt.Errorf("SSH agent is not running in agent mode"))
	}

	if err := d.sshAgent.Manager().RemoveIdentity(fingerprint); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to remove key: %w", err))
	}
	slog.Info("DBus: SSH key removed", "fingerprint", fingerprint)
	return true, nil
}

// CreatePasskey is reserved for the future passkey API.
func (d *DaemonDBus) CreatePasskey(sender dbus.Sender, uuid string, rpID string, rpName string, userName string, userDisplayName string, algorithms []int) (map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	return nil, dbus.MakeFailedError(fmt.Errorf("FIDO2/passkey API is not implemented"))
}

// AssertPasskey is reserved for the future passkey API.
func (d *DaemonDBus) AssertPasskey(sender dbus.Sender, rpID string, credentialID string, challenge string, origin string) (map[string]dbus.Variant, *dbus.Error) {
	if err := d.authorize(sender); err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	return nil, dbus.MakeFailedError(fmt.Errorf("FIDO2/passkey API is not implemented"))
}

// findEntryByPath searches for an entry by slash-separated path.
func findEntryByPath(db *dbpool.OpenDatabase, path string) *gokeepasslib.Entry {
	entries := db.RootEntries()
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
