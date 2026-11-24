//go:build linux

package secretservice

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/security"
)

// SecretService implements the org.freedesktop.Secret.Service D-Bus API.
// It exposes unlocked KeePass databases as collections and their entries as items.
type SecretService struct {
	conn            *dbus.Conn
	pool            *dbpool.DatabasePool
	config          config.SecretServiceConfig
	databaseConfigs []config.DatabaseConfig

	// mu protects collections, items, sessions, and aliases.
	mu sync.RWMutex

	// collections maps collection DBus paths to Collection objects.
	collections map[dbus.ObjectPath]*Collection

	// sessions maps session DBus paths to Session objects.
	sessions   map[dbus.ObjectPath]*Session
	sessionsMu sync.RWMutex

	// aliases maps alias names to collection paths.
	aliases map[string]dbus.ObjectPath

	// notifyCache suppresses repeat secret-access notifications per app.
	// The zero value is ready to use.
	notifyCache notifyCache

	// nextID for generating unique session/prompt paths.
	nextID uint64
}

// NewSecretService creates a new SecretService backed by the given DatabasePool.
func NewSecretService(pool *dbpool.DatabasePool, cfgs ...*config.SecretServiceConfig) *SecretService {
	cfg := config.DefaultConfig().SecretService
	if len(cfgs) > 0 && cfgs[0] != nil {
		cfg = *cfgs[0]
	}
	return &SecretService{
		pool:        pool,
		config:      cfg,
		collections: make(map[dbus.ObjectPath]*Collection),
		sessions:    make(map[dbus.ObjectPath]*Session),
		aliases:     make(map[string]dbus.ObjectPath),
	}
}

// UpdateConfig applies runtime-configurable Secret Service options after a
// daemon SIGHUP reload.
func (ss *SecretService) UpdateConfig(cfg config.SecretServiceConfig) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.config = cfg
}

// UpdateDatabaseConfigs applies per-database Secret Service exposure settings.
func (ss *SecretService) UpdateDatabaseConfigs(dbs []config.DatabaseConfig) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.databaseConfigs = append([]config.DatabaseConfig(nil), dbs...)
}

func (ss *SecretService) configSnapshot() config.SecretServiceConfig {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.config
}

func (ss *SecretService) exposeGroupForDB(db *dbpool.OpenDatabase) string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for _, cfg := range ss.databaseConfigs {
		if cfg.Path == db.Path || cfg.Name == db.Name {
			return cfg.SecretServiceExposeGroup
		}
	}
	return ""
}

func (ss *SecretService) collectEntriesForDB(db *dbpool.OpenDatabase) []gokeepasslib.Entry {
	if db.Db == nil || db.Db.Content == nil || db.Db.Content.Root == nil {
		return nil
	}
	recycleBinUUID := dbpool.RecycleBinUUIDForDB(db.Db)
	return collectEntriesVisible(db.Db.Content.Root.Groups, recycleBinUUID, ss.exposeGroupForDB(db))
}

// Export registers the Secret Service on the session bus.
// It claims the well-known name org.freedesktop.secrets and exports
// all interfaces using the godbus introspect package for proper discovery.
func (ss *SecretService) Export(conn *dbus.Conn) error {
	ss.conn = conn

	// Export the service interface at the root Secret Service path.
	if err := conn.Export(ss, ServicePath, InterfaceService); err != nil {
		return fmt.Errorf("secretservice: export service interface: %w", err)
	}

	// Build introspection node with method signatures auto-derived from the
	// SecretService struct, plus child node entries for D-Spy path traversal.
	node := &introspect.Node{
		Name: string(ServicePath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			propertiesIntrospectData(),
		},
		Children: []introspect.Node{
			{Name: "collection"},
			{Name: "session"},
			{Name: "prompt"},
		},
	}
	node.Interfaces = append(node.Interfaces, introspect.Interface{Name: InterfaceService, Methods: introspect.Methods(ss)})

	conn.Export(introspect.NewIntrospectable(node), ServicePath,
		"org.freedesktop.DBus.Introspectable")

	// Export a properties handler.
	conn.Export(NewProperties(ss), ServicePath,
		"org.freedesktop.DBus.Properties")

	// Claim the well-known name.
	reply, err := conn.RequestName("org.freedesktop.secrets",
		dbus.NameFlagReplaceExisting|dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("secretservice: request name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("secretservice: name org.freedesktop.secrets already owned (reply=%d)", reply)
	}

	slog.Info("secret service exported on session bus",
		"name", "org.freedesktop.secrets")

	// Seed existing unlocked databases as collections.
	ss.seedCollections()

	return nil
}

// seedCollections creates collections for all currently unlocked databases.
func (ss *SecretService) seedCollections() {
	dbs := ss.pool.List()
	for _, odb := range dbs {
		odb.RLock()
		if odb.Locked {
			odb.RUnlock()
			continue
		}
		odb.RUnlock()
		ss.createCollection(odb)
	}
}

// HandlePoolEvent processes a database pool event, creating or removing
// collections as databases are unlocked or locked.
func (ss *SecretService) HandlePoolEvent(evt dbpool.Event) {
	switch evt.Type {
	case dbpool.EventDatabaseUnlocked:
		ss.onDatabaseUnlocked(evt.UUID)
	case dbpool.EventDatabaseLocked:
		ss.onDatabaseLocked(evt.UUID)
	case dbpool.EventDatabaseReloaded:
		ss.onDatabaseReloaded(evt.UUID)
	}
}

// onDatabaseUnlocked creates a collection for the newly unlocked database.
func (ss *SecretService) onDatabaseUnlocked(uuid string) {
	odb, err := ss.pool.Get(uuid)
	if err != nil {
		slog.Warn("secretservice: cannot get database for event",
			"uuid", uuid, "error", err)
		return
	}
	ss.createCollection(odb)
	slog.Info("secretservice: collection created", "db", odb.Name)
}

// onDatabaseLocked removes the collection for the locked database.
func (ss *SecretService) onDatabaseLocked(uuid string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	for path, coll := range ss.collections {
		if coll.db.UUID == uuid {
			ss.removeCollectionLocked(path)
			slog.Info("secretservice: collection removed", "db", coll.db.Name)
		}
	}
}

// onDatabaseReloaded emits CollectionChanged for the database's collection.
// Collections read through to the live database, so no teardown/recreate is
// needed — and tearing down would drop custom aliases.
func (ss *SecretService) onDatabaseReloaded(uuid string) {
	ss.mu.RLock()
	var path dbus.ObjectPath
	for p, coll := range ss.collections {
		if coll.db.UUID == uuid {
			path = p
			break
		}
	}
	ss.mu.RUnlock()
	if path == "" || ss.conn == nil {
		return
	}
	if err := ss.conn.Emit(ServicePath, InterfaceService+".CollectionChanged", path); err != nil {
		slog.Warn("secretservice: emit CollectionChanged", "error", err)
	}
}

// createCollection registers a collection for the given database.
func (ss *SecretService) createCollection(odb *dbpool.OpenDatabase) {
	coll := newCollection(ss.conn, ss, odb)
	path := coll.Path()

	ss.mu.Lock()
	ss.collections[path] = coll
	ss.mu.Unlock()

	// Export the collection interface.
	if err := ss.conn.Export(coll, path, InterfaceCollection); err != nil {
		slog.Warn("secretservice: export collection interface",
			"path", path, "error", err)
		return
	}

	// Export introspection for the collection (auto-derive methods + properties).
	collNode := &introspect.Node{
		Name: string(path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:       InterfaceCollection,
				Methods:    introspect.Methods(coll),
				Properties: collectionIntrospectProperties(),
			},
			propertiesIntrospectData(),
		},
	}
	ss.conn.Export(introspect.NewIntrospectable(collNode), path,
		"org.freedesktop.DBus.Introspectable")

	// Export properties for the collection (per-object handler).
	ss.conn.Export(newCollectionProperties(coll), path,
		"org.freedesktop.DBus.Properties")

	// Export items within this collection.
	ss.exportItemsForCollection(coll)

	// Auto-assign "default" alias to the first collection (matches KeePassXC behavior).
	// VSCode/libsecret rely on ReadAlias("default") returning a valid collection.
	ss.mu.Lock()
	if _, exists := ss.aliases["default"]; !exists {
		ss.aliases["default"] = path
		ss.exportAlias("default", coll)
		slog.Debug("secretservice: assigned default alias", "collection", string(path))
	}
	ss.mu.Unlock()

	// Signal CollectionCreated (spec signal: a single object path).
	ss.emitCollectionCreated(path)
}

// exportAlias registers an alias path (/org/freedesktop/secrets/aliases/<alias>)
// that points to the given collection. libsecret clients commonly access the
// default collection through its alias path rather than the real collection path.
func (ss *SecretService) exportAlias(alias string, coll *Collection) {
	if ss.conn == nil {
		return
	}
	aliasPath := ss.aliasPath(alias)
	if err := ss.conn.Export(coll, aliasPath, InterfaceCollection); err != nil {
		slog.Warn("secretservice: export alias collection interface",
			"alias", alias, "path", aliasPath, "error", err)
		return
	}
	collNode := &introspect.Node{
		Name: string(aliasPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:       InterfaceCollection,
				Methods:    introspect.Methods(coll),
				Properties: collectionIntrospectProperties(),
			},
			propertiesIntrospectData(),
		},
	}
	if err := ss.conn.Export(introspect.NewIntrospectable(collNode), aliasPath,
		"org.freedesktop.DBus.Introspectable"); err != nil {
		slog.Warn("secretservice: export alias introspection",
			"alias", alias, "path", aliasPath, "error", err)
	}
	if err := ss.conn.Export(newCollectionProperties(coll), aliasPath,
		"org.freedesktop.DBus.Properties"); err != nil {
		slog.Warn("secretservice: export alias properties",
			"alias", alias, "path", aliasPath, "error", err)
	}
}

func (ss *SecretService) aliasPath(alias string) dbus.ObjectPath {
	return dbus.ObjectPath(ServicePath + "/aliases/" + alias)
}

// removeCollectionLocked removes a collection and everything bound to it:
// its aliases are unexported and dropped, and the "default" alias is rebound
// to a remaining collection (or removed when none remain). Emits the spec
// CollectionDeleted signal. Must be called with ss.mu held.
func (ss *SecretService) removeCollectionLocked(path dbus.ObjectPath) {
	coll, existed := ss.collections[path]
	delete(ss.collections, path)

	if existed && ss.conn != nil {
		// Unexport the collection and every exported item under it, so no
		// stale object remains reachable on the bus after removal.
		_ = ss.conn.Export(nil, path, InterfaceCollection)
		_ = ss.conn.Export(nil, path, "org.freedesktop.DBus.Introspectable")
		_ = ss.conn.Export(nil, path, "org.freedesktop.DBus.Properties")
		coll.db.RLock()
		for _, entry := range ss.collectEntriesForDB(coll.db) {
			itemPath := itemPathForDB(coll.db, entry)
			_ = ss.conn.Export(nil, itemPath, InterfaceItem)
			_ = ss.conn.Export(nil, itemPath, "org.freedesktop.DBus.Introspectable")
			_ = ss.conn.Export(nil, itemPath, "org.freedesktop.DBus.Properties")
		}
		coll.db.RUnlock()
	}

	for alias, target := range ss.aliases {
		if target != path {
			continue
		}
		aliasPath := ss.aliasPath(alias)
		if ss.conn != nil {
			_ = ss.conn.Export(nil, aliasPath, InterfaceCollection)
			_ = ss.conn.Export(nil, aliasPath, "org.freedesktop.DBus.Introspectable")
			_ = ss.conn.Export(nil, aliasPath, "org.freedesktop.DBus.Properties")
		}
		delete(ss.aliases, alias)
	}

	// Rebind "default" to a remaining collection, deterministically.
	if len(ss.collections) > 0 {
		remaining := make([]string, 0, len(ss.collections))
		for p := range ss.collections {
			remaining = append(remaining, string(p))
		}
		slices.Sort(remaining)
		if _, ok := ss.aliases["default"]; !ok {
			target := dbus.ObjectPath(remaining[0])
			ss.aliases["default"] = target
			ss.exportAlias("default", ss.collections[target])
		}
	}

	ss.emitCollectionDeleted(path)
}

// exportItemsForCollection exports all items for a collection.
func (ss *SecretService) exportItemsForCollection(coll *Collection) {
	coll.db.RLock()
	entries := ss.collectEntriesForDB(coll.db)
	coll.db.RUnlock()

	for _, entry := range entries {
		item := newItem(ss.conn, coll, entry)
		path := item.Path()

		// Export item interface.
		if err := ss.conn.Export(item, path, InterfaceItem); err != nil {
			slog.Warn("secretservice: export item interface",
				"path", path, "error", err)
			continue
		}

		// Export introspection with correct GetSecret signature.
		ss.conn.Export(introspect.NewIntrospectable(itemIntrospectNode(item)), path,
			"org.freedesktop.DBus.Introspectable")

		// Export per-item properties.
		ss.conn.Export(newItemProperties(item), path,
			"org.freedesktop.DBus.Properties")
	}
}

// itemsForCollection returns all items registered for a given collection path.
func (ss *SecretService) itemsForCollection(collPath dbus.ObjectPath) []*Item {
	var items []*Item
	ss.mu.RLock()
	coll, ok := ss.collections[collPath]
	ss.mu.RUnlock()
	if !ok {
		return items
	}

	coll.db.RLock()
	defer coll.db.RUnlock()
	if coll.db.Locked || coll.db.Db == nil || coll.db.Db.Content == nil {
		return items
	}

	entries := ss.collectEntriesForDB(coll.db)
	items = make([]*Item, 0, len(entries))
	for _, entry := range entries {
		item := newItem(ss.conn, coll, entry)
		items = append(items, item)
	}
	return items
}

// emitCollectionCreated emits the spec CollectionCreated signal (one path).
func (ss *SecretService) emitCollectionCreated(path dbus.ObjectPath) {
	if ss.conn == nil {
		return
	}
	if err := ss.conn.Emit(ServicePath, InterfaceService+".CollectionCreated", path); err != nil {
		slog.Warn("secretservice: emit CollectionCreated", "error", err)
	}
}

// emitCollectionDeleted emits the spec CollectionDeleted signal (one path).
func (ss *SecretService) emitCollectionDeleted(path dbus.ObjectPath) {
	if ss.conn == nil {
		return
	}
	if err := ss.conn.Emit(ServicePath, InterfaceService+".CollectionDeleted", path); err != nil {
		slog.Warn("secretservice: emit CollectionDeleted", "error", err)
	}
}

// ---- org.freedesktop.Secret.Service methods ----

// registerSession stores a session under the session-map mutex. All reads
// and writes of ss.sessions must go through sessionsMu (never ss.mu): the
// two mutexes were used inconsistently before, which allowed a fatal
// concurrent map read/write.
func (ss *SecretService) registerSession(path dbus.ObjectPath, sess *Session) {
	sess.onClose = func() {
		ss.sessionsMu.Lock()
		delete(ss.sessions, path)
		ss.sessionsMu.Unlock()
		// Unexport the session object and wipe its key: Close must not leave
		// the AES key reachable on the bus or in memory.
		if ss.conn != nil {
			_ = ss.conn.Export(nil, path, InterfaceSession)
			_ = ss.conn.Export(nil, path, "org.freedesktop.DBus.Introspectable")
		}
		sess.wipeKey()
	}
	ss.sessionsMu.Lock()
	ss.sessions[path] = sess
	ss.sessionsMu.Unlock()
}

// getSession returns the session for path, or nil.
func (ss *SecretService) getSession(path dbus.ObjectPath) *Session {
	ss.sessionsMu.RLock()
	defer ss.sessionsMu.RUnlock()
	return ss.sessions[path]
}

// OpenSession negotiates a session for encrypted secret transfer.
func (ss *SecretService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: OpenSession", "algorithm", algorithm)
	ss.mu.Lock()
	defer ss.mu.Unlock()

	sessionID := ss.generateID()
	sessionPath := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/secrets/session/%s", sessionID))

	var output dbus.Variant

	switch algorithm {
	case "plain":
		output = dbus.MakeVariant("")
		sess := NewPlainSession(ss.conn, sessionPath)
		ss.registerSession(sessionPath, sess)

	case "dh-ietf1024-sha256-aes128-cbc", "dh-ietf1024-sha256-aes128-cbc-pkcs7":
		output = ss.handleDHKeyExchange(input, sessionPath)
		if output == (dbus.Variant{}) {
			return dbus.Variant{}, "/", dbus.NewError(ErrIsLocked,
				[]interface{}{"Failed to negotiate session"})
		}

	default:
		// Spec requires NotSupported for unknown algorithms.
		return dbus.Variant{}, "/", dbus.NewError("org.freedesktop.DBus.Error.NotSupported",
			[]interface{}{"Unsupported algorithm: " + algorithm})
	}

	// Export the session object (including Close) with introspection.
	sess := ss.getSession(sessionPath)
	if sess == nil {
		return dbus.Variant{}, "/", dbus.NewError(ErrNoSession,
			[]interface{}{"Session was not created"})
	}
	if err := ss.conn.Export(sess, sessionPath, InterfaceSession); err != nil {
		slog.Warn("secretservice: failed to export session", "path", string(sessionPath), "error", err)
	}

	sessNode := &introspect.Node{
		Name: string(sessionPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
		},
	}
	sessNode.Interfaces = append(sessNode.Interfaces, introspect.Interface{Name: InterfaceSession, Methods: introspect.Methods(sess)})
	ss.conn.Export(introspect.NewIntrospectable(sessNode), sessionPath,
		"org.freedesktop.DBus.Introspectable")

	slog.Debug("secretservice: session created", "path", string(sessionPath))
	return output, sessionPath, nil
}

// handleDHKeyExchange performs the DH key exchange for encrypted sessions.
// Input: variant containing the client's public key as byte array (ay).
// Output: variant containing the server's public key as byte array (ay).
func (ss *SecretService) handleDHKeyExchange(input dbus.Variant, sessionPath dbus.ObjectPath) dbus.Variant {
	// The client sends its DH public key as a byte array inside the variant.
	clientPubBytes, ok := input.Value().([]byte)
	if !ok {
		// Some clients wrap it — try nested extraction.
		if slice, ok := input.Value().([]interface{}); ok && len(slice) > 0 {
			clientPubBytes, ok = slice[0].([]byte)
		}
		if !ok {
			slog.Warn("secretservice: DH exchange: invalid client public key")
			return dbus.Variant{}
		}
	}

	privKey, pubKey := generateDHKeyPair()

	clientPub := new(big.Int).SetBytes(clientPubBytes)
	prime := dhPrime()
	// Reject out-of-range public keys instead of computing a degenerate
	// shared secret (fail closed on malformed input): valid range [2, p-2].
	two := big.NewInt(2)
	if clientPub.Cmp(two) < 0 || clientPub.Cmp(new(big.Int).Sub(prime, two)) > 0 {
		slog.Warn("secretservice: DH exchange: client public key out of range")
		return dbus.Variant{}
	}
	sharedSecret := new(big.Int).Exp(clientPub, privKey, prime)
	key := DeriveSessionKey(sharedSecret.Bytes())

	sess := NewEncryptedSession(ss.conn, sessionPath, key)
	ss.registerSession(sessionPath, sess)

	// Return just the server's public key as a byte array variant.
	output := dbus.MakeVariant(pubKey.Bytes())

	return output
}

// generateID generates a unique ID. Must be called with ss.mu held.
func (ss *SecretService) generateID() string {
	id := ss.nextID
	ss.nextID++
	return fmt.Sprintf("s%d", id)
}

// CreateCollection creates a new collection. Since kpxcd is read-only
// with respect to the database, this returns a not-supported error.
// CreateCollection refuses: kpxcd exposes existing KeePass databases as
// collections and cannot create new ones. Returning a prompt that never
// yields a collection would hang clients.
func (ss *SecretService) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: CreateCollection refused", "alias", alias)
	return "/", "/", dbus.NewError("org.freedesktop.DBus.Error.NotSupported",
		[]interface{}{"kpxcd does not create collections; unlock a KeePass database instead"})
}

// SearchItems searches for items across all collections matching the attributes.
func (ss *SecretService) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: SearchItems", "attributes", attributes)
	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath

	ss.mu.RLock()
	collections := make([]*Collection, 0, len(ss.collections))
	for _, coll := range ss.collections {
		collections = append(collections, coll)
	}
	ss.mu.RUnlock()

	for _, coll := range collections {
		coll.db.RLock()
		if coll.db.Locked || coll.db.Db == nil || coll.db.Db.Content == nil {
			coll.db.RUnlock()
			continue
		}

		entries := ss.collectEntriesForDB(coll.db)
		for _, entry := range entries {
			if MatchAttributes(entry, coll.db, attributes) {
				itemPath := itemPathForDB(coll.db, entry)
				slog.Debug("secretservice: SearchItems match", "path", itemPath, "title", entry.GetTitle())
				unlocked = append(unlocked, dbus.ObjectPath(itemPath))
			}
		}
		coll.db.RUnlock()
	}

	slog.Debug("secretservice: SearchItems result", "unlocked", len(unlocked), "locked", len(locked))
	return unlocked, locked, nil
}

// Unlock unlocks the given objects.
func (ss *SecretService) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: Unlock", "objects", objects)
	var unlocked []dbus.ObjectPath

	for _, path := range objects {
		if coll, ok := ss.getCollectionByPath(path); ok {
			if !coll.Locked() {
				unlocked = append(unlocked, path)
			}
		} else if _, ok := ss.getItemByPath(path); ok {
			unlocked = append(unlocked, path)
		}
	}

	// Only return a prompt if there are objects that actually need unlocking.
	// KeePassXC returns prompt=nullptr ("/") when everything is already unlocked
	// or the list is empty.
	var needsUnlock bool
	for _, path := range objects {
		if coll, ok := ss.getCollectionByPath(path); ok && coll.Locked() {
			needsUnlock = true
			break
		}
	}
	if !needsUnlock {
		return unlocked, "/", nil
	}

	// A locked collection maps to a locked database, which only the user can
	// unlock (kpxcctl unlock / PAM). Fail closed instead of returning a
	// prompt that completes without unlocking anything.
	return unlocked, "/", dbus.NewError(ErrIsLocked,
		[]interface{}{"collection is backed by a locked database; unlock it with kpxcctl"})
}

// Lock locks the given objects.
func (ss *SecretService) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: Lock", "objects", objects)
	var locked []dbus.ObjectPath

	for _, path := range objects {
		if coll, ok := ss.getCollectionByPath(path); ok {
			if err := ss.pool.Lock(coll.db.UUID); err == nil {
				locked = append(locked, path)
			}
		}
	}

	// Locking happened synchronously above; a prompt could never change the
	// outcome, so always return the null prompt "/".
	return locked, "/", nil
}

// GetSecrets retrieves secrets for the given items using the specified session.
func (ss *SecretService) GetSecrets(sender dbus.Sender, items []dbus.ObjectPath, sessionPath dbus.ObjectPath) (map[dbus.ObjectPath]DBusSecret, *dbus.Error) {
	slog.Debug("secretservice: GetSecrets", "items", items, "session", string(sessionPath), "sender", string(sender))
	secrets := make(map[dbus.ObjectPath]DBusSecret)
	caller := ss.callerInfo(sender)

	sess := ss.getSession(sessionPath)
	if sess == nil {
		return secrets, dbus.NewError(ErrNoSession,
			[]interface{}{"No such session"})
	}
	if sess.isClosed() {
		return secrets, dbus.NewError(ErrNoSession,
			[]interface{}{"Session is closed"})
	}

	for _, itemPath := range items {
		item, ok := ss.getItemByPath(itemPath)
		if !ok {
			slog.Debug("secretservice: GetSecrets item not found", "path", string(itemPath))
			continue
		}

		if err := ss.authorizeSecretAccess(caller, item); err != nil {
			slog.Warn("secretservice: secret access denied",
				"sender", caller.Sender,
				"pid", caller.PID,
				"app", caller.AppName(),
				"collection", item.coll.db.Name,
				"item", item.Label(),
				"error", err)
			return secrets, dbus.NewError(ErrAccessDenied,
				[]interface{}{err.Error()})
		}

		var iv []byte
		var ciphertext []byte
		var secretErr error
		security.Do(func() {
			item.db.RLock()
			password := item.entry.GetPassword()
			item.db.RUnlock()
			iv, ciphertext, secretErr = sess.Encrypt([]byte(password))
		})
		if secretErr != nil {
			slog.Warn("secretservice: encrypt failed", "error", secretErr)
			continue
		}

		secrets[itemPath] = DBusSecret{
			Session:     sessionPath,
			Parameters:  iv,
			Value:       ciphertext,
			ContentType: "text/plain",
		}
		ss.logSecretAccess(caller, item, "Service.GetSecrets")
		ss.notifySecretAccess(caller, item)
	}

	slog.Debug("secretservice: GetSecrets result", "count", len(secrets))
	return secrets, nil
}

// ReadAlias returns the collection path for the given alias.
func (ss *SecretService) ReadAlias(alias string) (dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: ReadAlias", "alias", alias)
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	_, ok := ss.aliases[alias]
	if !ok {
		return "/", nil
	}
	return ss.aliasPath(alias), nil
}

// SetAlias sets an alias for a collection.
func (ss *SecretService) SetAlias(alias string, collectionPath dbus.ObjectPath) *dbus.Error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	coll, ok := ss.collections[collectionPath]
	if !ok {
		return dbus.NewError(ErrNoSuchObject,
			[]interface{}{"No such collection"})
	}

	ss.aliases[alias] = collectionPath
	ss.exportAlias(alias, coll)
	return nil
}

// getCollectionByPath looks up a collection by its DBus path. It also resolves
// alias paths (e.g. /org/freedesktop/secrets/aliases/default) to the underlying
// collection, because libsecret clients commonly call Unlock/Lock on the alias.
func (ss *SecretService) getCollectionByPath(path dbus.ObjectPath) (*Collection, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	if coll, ok := ss.collections[path]; ok {
		return coll, true
	}
	for alias, target := range ss.aliases {
		if ss.aliasPath(alias) == path {
			if coll, ok := ss.collections[target]; ok {
				return coll, true
			}
		}
	}
	return nil, false
}

// getItemByPath looks up an item by its DBus path.
func (ss *SecretService) getItemByPath(path dbus.ObjectPath) (*Item, bool) {
	ss.mu.RLock()
	collections := make([]*Collection, 0, len(ss.collections))
	for _, coll := range ss.collections {
		collections = append(collections, coll)
	}
	ss.mu.RUnlock()

	for _, coll := range collections {
		coll.db.RLock()
		if coll.db.Locked || coll.db.Db == nil || coll.db.Db.Content == nil {
			coll.db.RUnlock()
			continue
		}
		entries := ss.collectEntriesForDB(coll.db)
		for _, entry := range entries {
			itemPath := itemPathForDB(coll.db, entry)
			if dbus.ObjectPath(itemPath) == path {
				item := newItem(ss.conn, coll, entry)
				coll.db.RUnlock()
				return item, true
			}
		}
		coll.db.RUnlock()
	}
	return nil, false
}

// nextPromptPath generates a new prompt object path.
// nextPrompt creates a new prompt, exports it on the bus, and returns its path.
func (ss *SecretService) nextPrompt() (*Prompt, dbus.ObjectPath) {
	ss.mu.Lock()
	id := ss.nextID
	ss.nextID++
	ss.mu.Unlock()

	path := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/secrets/prompt/p%d", id))
	prompt := NewPrompt(ss.conn, path)

	// Export the prompt interface.
	if ss.conn != nil {
		if err := ss.conn.Export(prompt, path, InterfacePrompt); err != nil {
			slog.Warn("secretservice: failed to export prompt", "path", path, "error", err)
		}
	}

	return prompt, path
}

// ---- DH parameter generation ----

func dhPrime() *big.Int {
	primeHex := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
		"FFFFFFFFFFFFFFFF"
	p, _ := new(big.Int).SetString(primeHex, 16)
	return p
}

func generateDHKeyPair() (priv *big.Int, pub *big.Int) {
	prime := dhPrime()
	generator := big.NewInt(2)

	// Generate a random private key using crypto/rand.
	// Must be in range [2, prime-2] for security.
	privBytes := make([]byte, 128) // 1024 bits
	if _, err := rand.Read(privBytes); err != nil {
		// Fallback should never happen on Linux.
		panic("secretservice: crypto/rand failed: " + err.Error())
	}
	priv = new(big.Int).SetBytes(privBytes)
	priv.Mod(priv, new(big.Int).Sub(prime, big.NewInt(2)))
	priv.Add(priv, big.NewInt(2))

	pub = new(big.Int).Exp(generator, priv, prime)
	return priv, pub
}
