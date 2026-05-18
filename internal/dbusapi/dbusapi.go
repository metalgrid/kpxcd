//go:build linux

// Package dbusapi implements the org.keepassxc.Daemon DBus interface.
package dbusapi

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/user/kpxcd/internal/config"
	"github.com/user/kpxcd/internal/dbpool"
	"github.com/user/kpxcd/internal/fido2"
	"github.com/user/kpxcd/internal/security"
)

// DaemonDBus implements the org.keepassxc.Daemon DBus interface.
type DaemonDBus struct {
	conn    *dbus.Conn
	config  *config.Config
	pool    *dbpool.DatabasePool
	fido2   *fido2.Fido2Service
}

// NewDaemonDBus creates a new DBus API handler.
func NewDaemonDBus(cfg *config.Config, pool *dbpool.DatabasePool, f2 *fido2.Fido2Service) *DaemonDBus {
	return &DaemonDBus{
		config: cfg,
		pool:   pool,
		fido2:  f2,
	}
}

// NewDaemonDBusWithConn creates a DBus API handler with an existing connection.
// Use this when sharing a bus connection with other DBus services (e.g. Secret Service).
func NewDaemonDBusWithConn(cfg *config.Config, pool *dbpool.DatabasePool, f2 *fido2.Fido2Service, conn *dbus.Conn) *DaemonDBus {
	return &DaemonDBus{
		config: cfg,
		pool:   pool,
		fido2:  f2,
		conn:   conn,
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

	// Export the object.
	path := dbus.ObjectPath("/org/keepassxc/Daemon")
	if err := d.conn.Export(d, path, "org.keepassxc.Daemon"); err != nil {
		d.conn.Close()
		return fmt.Errorf("dbusapi: failed to export object: %w", err)
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

// Ping responds with "pong".
func (d *DaemonDBus) Ping() (string, *dbus.Error) {
	return "pong", nil
}

// ListDatabases returns all known databases.
func (d *DaemonDBus) ListDatabases() ([]map[string]dbus.Variant, *dbus.Error) {
	dbs := d.pool.List()
	result := make([]map[string]dbus.Variant, len(dbs))

	for i, db := range dbs {
		result[i] = map[string]dbus.Variant{
			"uuid":       dbus.MakeVariant(db.UUID),
			"name":       dbus.MakeVariant(db.Name),
			"path":       dbus.MakeVariant(db.Path),
			"locked":     dbus.MakeVariant(db.Locked),
			"auto_unlock": dbus.MakeVariant(false), // TODO: from config
		}
	}

	return result, nil
}

// UnlockDatabase unlocks a database by path.
func (d *DaemonDBus) UnlockDatabase(path string, credentialType string, credential dbus.Variant) (bool, *dbus.Error) {
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

	slog.Info("DBus: database unlocked", "uuid", uuid, "path", path)
	return true, nil
}

// LockDatabase locks a database by UUID.
func (d *DaemonDBus) LockDatabase(uuid string) (bool, *dbus.Error) {
	if err := d.pool.Lock(uuid); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to lock database: %w", err))
	}
	slog.Info("DBus: database locked", "uuid", uuid)
	return true, nil
}

// LockAll locks all databases.
func (d *DaemonDBus) LockAll() (bool, *dbus.Error) {
	if err := d.pool.LockAll(); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("failed to lock databases: %w", err))
	}
	slog.Info("DBus: all databases locked")
	return true, nil
}

// GetEntry retrieves entry fields by database UUID and entry path.
func (d *DaemonDBus) GetEntry(uuid string, entryPath string) (map[string]dbus.Variant, *dbus.Error) {
	db, err := d.pool.Get(uuid)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("database not found: %w", err))
	}
	if db.Locked {
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
		"password": dbus.MakeVariant(entry.GetPassword()),
		"url":      dbus.MakeVariant(entry.GetContent("URL")),
		"notes":    dbus.MakeVariant(entry.GetContent("Notes")),
		"uuid":     dbus.MakeVariant(string(entry.UUID[:])),
	}

	return result, nil
}

// SearchEntries searches entries by query.
func (d *DaemonDBus) SearchEntries(uuid string, query string) ([]map[string]dbus.Variant, *dbus.Error) {
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
		if db.Locked {
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
func (d *DaemonDBus) GetTotp(uuid string, entryPath string) (string, *dbus.Error) {
	// TODO: Implement TOTP using github.com/pquerna/otp
	return "", dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// GeneratePassword generates a random password.
func (d *DaemonDBus) GeneratePassword(length int, charset string) (string, *dbus.Error) {
	// TODO: Implement password generation
	return "", dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// GeneratePassphrase generates a diceware passphrase.
func (d *DaemonDBus) GeneratePassphrase(wordCount int, separator string) (string, *dbus.Error) {
	// TODO: Implement passphrase generation
	return "", dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// SshListKeys lists SSH keys in a database.
func (d *DaemonDBus) SshListKeys(uuid string) ([]map[string]dbus.Variant, *dbus.Error) {
	// TODO: Integrate with sshagent.IdentityManager
	return nil, dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// SshAddKey adds an SSH key to the agent.
func (d *DaemonDBus) SshAddKey(uuid string, entryPath string, lifetime uint32, confirm bool) (bool, *dbus.Error) {
	// TODO: Integrate with sshagent.AgentServer
	return false, dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// SshRemoveKey removes an SSH key from the agent.
func (d *DaemonDBus) SshRemoveKey(fingerprint string) (bool, *dbus.Error) {
	// TODO: Integrate with sshagent.AgentServer
	return false, dbus.MakeFailedError(fmt.Errorf("not yet implemented"))
}

// CreatePasskey creates a new FIDO2 credential.
func (d *DaemonDBus) CreatePasskey(uuid string, rpID string, rpName string, userName string, userDisplayName string, algorithms []int) (map[string]dbus.Variant, *dbus.Error) {
	if d.fido2 == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("FIDO2 service is disabled"))
	}

	entry, err := d.fido2.CreatePasskey(uuid, rpID, rpName, userName, userDisplayName, algorithms)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("failed to create passkey: %w", err))
	}

	return map[string]dbus.Variant{
		"credential_id": dbus.MakeVariant(entry.CredentialID),
		"public_key":    dbus.MakeVariant(fmt.Sprintf("%x", entry.PublicKeyCOSE)),
		"entry_path":    dbus.MakeVariant(entry.Subject),
	}, nil
}

// AssertPasskey performs a FIDO2 assertion.
func (d *DaemonDBus) AssertPasskey(rpID string, credentialID string, challenge string, origin string) (map[string]dbus.Variant, *dbus.Error) {
	if d.fido2 == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("FIDO2 service is disabled"))
	}

	result, err := d.fido2.AssertPasskey(rpID, credentialID, challenge, origin)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("failed to assert passkey: %w", err))
	}

	return map[string]dbus.Variant{
		"authenticator_data": dbus.MakeVariant(result.AuthenticatorData),
		"signature":          dbus.MakeVariant(result.Signature),
		"user_handle":        dbus.MakeVariant(result.UserHandle),
	}, nil
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
