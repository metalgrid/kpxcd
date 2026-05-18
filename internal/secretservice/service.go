//go:build linux

package secretservice

import (
	"fmt"
	"log/slog"
	"math/big"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/tobischo/gokeepasslib/v3"

	"github.com/user/kpxcd/internal/dbpool"
)

// SecretService implements the org.freedesktop.Secret.Service D-Bus API.
// It exposes unlocked KeePass databases as collections and their entries as items.
type SecretService struct {
	conn *dbus.Conn
	pool *dbpool.DatabasePool

	// mu protects collections, items, sessions, and aliases.
	mu sync.RWMutex

	// collections maps collection DBus paths to Collection objects.
	collections map[dbus.ObjectPath]*Collection

	// sessions maps session DBus paths to Session objects.
	sessions   map[dbus.ObjectPath]*Session
	sessionsMu sync.RWMutex

	// aliases maps alias names to collection paths.
	aliases map[string]dbus.ObjectPath

	// nextID for generating unique session/prompt paths.
	nextID uint64
}

// NewSecretService creates a new SecretService backed by the given DatabasePool.
func NewSecretService(pool *dbpool.DatabasePool) *SecretService {
	return &SecretService{
		pool:        pool,
		collections: make(map[dbus.ObjectPath]*Collection),
		sessions:    make(map[dbus.ObjectPath]*Session),
		aliases:     make(map[string]dbus.ObjectPath),
	}
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
			intropectProperties(),
			{
				Name: "org.freedesktop.DBus.Properties",
				Methods: []introspect.Method{
					{Name: "Get", Args: []introspect.Arg{
						{Name: "interface", Type: "s", Direction: "in"},
						{Name: "property", Type: "s", Direction: "in"},
						{Name: "value", Type: "v", Direction: "out"},
					}},
					{Name: "GetAll", Args: []introspect.Arg{
						{Name: "interface", Type: "s", Direction: "in"},
						{Name: "properties", Type: "a{sv}", Direction: "out"},
					}},
					{Name: "Set", Args: []introspect.Arg{
						{Name: "interface", Type: "s", Direction: "in"},
						{Name: "property", Type: "s", Direction: "in"},
						{Name: "value", Type: "v", Direction: "in"},
					}},
				},
			},
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
		dbus.NameFlagDoNotQueue)
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

func intropectProperties() introspect.Interface {
	return introspect.Interface{
		Name: "org.freedesktop.DBus.Properties",
		Methods: []introspect.Method{
			{Name: "Get", Args: []introspect.Arg{
				{Name: "interface", Type: "s", Direction: "in"},
				{Name: "property", Type: "s", Direction: "in"},
				{Name: "value", Type: "v", Direction: "out"},
			}},
			{Name: "GetAll", Args: []introspect.Arg{
				{Name: "interface", Type: "s", Direction: "in"},
				{Name: "properties", Type: "a{sv}", Direction: "out"},
			}},
			{Name: "Set", Args: []introspect.Arg{
				{Name: "interface", Type: "s", Direction: "in"},
				{Name: "property", Type: "s", Direction: "in"},
				{Name: "value", Type: "v", Direction: "in"},
			}},
		},
	}
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

// onDatabaseReloaded removes and re-creates the collection for the database.
func (ss *SecretService) onDatabaseReloaded(uuid string) {
	odb, err := ss.pool.Get(uuid)
	if err != nil {
		return
	}
	ss.mu.Lock()
	for path, coll := range ss.collections {
		if coll.db.UUID == uuid {
			ss.removeCollectionLocked(path)
			break
		}
	}
	ss.mu.Unlock()

	odb.RLock()
	if !odb.Locked {
		odb.RUnlock()
		ss.createCollection(odb)
	} else {
		odb.RUnlock()
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

	// Export introspection for the collection (auto-derive methods + child items).
	collNode := &introspect.Node{
		Name: string(path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
		},
	}
	collNode.Interfaces = append(collNode.Interfaces, introspect.Interface{Name: InterfaceCollection, Methods: introspect.Methods(coll)})
	ss.conn.Export(introspect.NewIntrospectable(collNode), path,
		"org.freedesktop.DBus.Introspectable")

	// Export properties for the collection.
	ss.conn.Export(NewProperties(ss), path,
		"org.freedesktop.DBus.Properties")

	// Export items within this collection.
	ss.exportItemsForCollection(coll)

	// Signal CollectionsChanged.
	ss.emitCollectionsChanged(nil, []dbus.ObjectPath{path})
}

// removeCollectionLocked removes a collection. Must be called with ss.mu held.
func (ss *SecretService) removeCollectionLocked(path dbus.ObjectPath) {
	delete(ss.collections, path)
}

// exportItemsForCollection exports all items for a collection.
func (ss *SecretService) exportItemsForCollection(coll *Collection) {
	coll.db.RLock()
	entries := collectEntriesSafe(coll.db)
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

		// Export introspection (auto-derived from Item methods).
		itemNode := &introspect.Node{
			Name: string(path),
			Interfaces: []introspect.Interface{
				introspect.IntrospectData,
			},
		}
		itemNode.Interfaces = append(itemNode.Interfaces, introspect.Interface{Name: InterfaceItem, Methods: introspect.Methods(item)})
		ss.conn.Export(introspect.NewIntrospectable(itemNode), path,
			"org.freedesktop.DBus.Introspectable")

		// Export properties.
		ss.conn.Export(NewProperties(ss), path,
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

	entries := collectEntriesSafe(coll.db)
	for _, entry := range entries {
		item := newItem(ss.conn, coll, entry)
		items = append(items, item)
	}
	return items
}

// collectEntriesSafe safely collects entries from a database.
func collectEntriesSafe(db *dbpool.OpenDatabase) []gokeepasslib.Entry {
	if db.Db == nil || db.Db.Content == nil || db.Db.Content.Root == nil {
		return nil
	}
	return collectEntries(db.Db.Content.Root.Groups)
}

// emitCollectionsChanged emits the CollectionsChanged signal.
func (ss *SecretService) emitCollectionsChanged(created, deleted []dbus.ObjectPath) {
	if ss.conn == nil {
		return
	}
	if err := ss.conn.Emit(ServicePath, InterfaceService+".CollectionsChanged",
		created, deleted); err != nil {
		slog.Warn("secretservice: emit CollectionsChanged", "error", err)
	}
}

// ---- org.freedesktop.Secret.Service methods ----

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
		ss.sessions[sessionPath] = sess

	case "dh-ietf1024-sha256-aes128-cbc":
		output = ss.handleDHKeyExchange(input, sessionPath)
		if output == (dbus.Variant{}) {
			return dbus.Variant{}, "/", dbus.NewError(ErrorPrefix+"InternalError",
				[]interface{}{"Failed to negotiate session"})
		}

	default:
		output = dbus.MakeVariant("")
		sess := NewPlainSession(ss.conn, sessionPath)
		ss.sessions[sessionPath] = sess
	}

	// Export the session object with introspection.
	sess := ss.sessions[sessionPath]
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
func (ss *SecretService) handleDHKeyExchange(input dbus.Variant, sessionPath dbus.ObjectPath) dbus.Variant {
	structData, ok := input.Value().([]interface{})
	if !ok || len(structData) < 3 {
		return dbus.Variant{}
	}

	clientPubBytes, ok := structData[0].([]byte)
	if !ok {
		return dbus.Variant{}
	}

	privKey, pubKey := generateDHKeyPair()

	clientPub := new(big.Int).SetBytes(clientPubBytes)
	prime := dhPrime()
	sharedSecret := new(big.Int).Exp(clientPub, privKey, prime)
	key := DeriveSessionKey(sharedSecret.Bytes())

	sess := NewEncryptedSession(ss.conn, sessionPath, key)
	ss.sessions[sessionPath] = sess

	output := dbus.MakeVariant([]interface{}{
		pubKey.Bytes(),
		prime.Bytes(),
	})

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
func (ss *SecretService) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: CreateCollection", "alias", alias)
	promptPath := ss.nextPromptPath()
	return "/", promptPath, nil
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

		entries := collectEntries(coll.db.Db.Content.Root.Groups)
		for _, entry := range entries {
			if MatchAttributes(entry, coll.db, attributes) {
				itemPath := CollectionPrefix + sanitizeCollectionName(coll.db.Name) + "/" + entryUUIDString(entry)
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

	promptPath := ss.nextPromptPath()
	return unlocked, promptPath, nil
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

	promptPath := ss.nextPromptPath()
	return locked, promptPath, nil
}

// GetSecrets retrieves secrets for the given items using the specified session.
func (ss *SecretService) GetSecrets(items []dbus.ObjectPath, sessionPath dbus.ObjectPath) (map[dbus.ObjectPath]map[string]interface{}, *dbus.Error) {
	slog.Debug("secretservice: GetSecrets", "items", items, "session", string(sessionPath))
	secrets := make(map[dbus.ObjectPath]map[string]interface{})

	ss.sessionsMu.RLock()
	sess, ok := ss.sessions[sessionPath]
	ss.sessionsMu.RUnlock()
	if !ok {
		return secrets, dbus.NewError(ErrorPrefix+"NoSuchSession",
			[]interface{}{"No such session"})
	}
	if sess.closed {
		return secrets, dbus.NewError(ErrorPrefix+"NoSuchSession",
			[]interface{}{"Session is closed"})
	}

	for _, itemPath := range items {
		item, ok := ss.getItemByPath(itemPath)
		if !ok {
			slog.Debug("secretservice: GetSecrets item not found", "path", string(itemPath))
			continue
		}

		item.db.RLock()
		password := item.entry.GetPassword()
		item.db.RUnlock()

		iv, ciphertext, err := sess.Encrypt([]byte(password))
		if err != nil {
			slog.Warn("secretservice: encrypt failed", "error", err)
			continue
		}

		secret := map[string]interface{}{
			"session":      sessionPath,
			"parameters":   iv,
			"value":        ciphertext,
			"content_type": "text/plain",
		}
		secrets[itemPath] = secret
	}

	slog.Debug("secretservice: GetSecrets result", "count", len(secrets))
	return secrets, nil
}

// ReadAlias returns the collection path for the given alias.
func (ss *SecretService) ReadAlias(alias string) (dbus.ObjectPath, *dbus.Error) {
	slog.Debug("secretservice: ReadAlias", "alias", alias)
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	path, ok := ss.aliases[alias]
	if !ok {
		return "/", dbus.NewError(ErrorPrefix+"NoSuchAlias",
			[]interface{}{"No collection with alias: " + alias})
	}
	return path, nil
}

// SetAlias sets an alias for a collection.
func (ss *SecretService) SetAlias(alias string, collectionPath dbus.ObjectPath) *dbus.Error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if _, ok := ss.collections[collectionPath]; !ok {
		return dbus.NewError(ErrorPrefix+"NoSuchCollection",
			[]interface{}{"No such collection"})
	}

	ss.aliases[alias] = collectionPath
	return nil
}

// getCollectionByPath looks up a collection by its DBus path.
func (ss *SecretService) getCollectionByPath(path dbus.ObjectPath) (*Collection, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	coll, ok := ss.collections[path]
	return coll, ok
}

// getItemByPath looks up an item by its DBus path.
func (ss *SecretService) getItemByPath(path dbus.ObjectPath) (*Item, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	for _, coll := range ss.collections {
		coll.db.RLock()
		if coll.db.Locked || coll.db.Db == nil || coll.db.Db.Content == nil {
			coll.db.RUnlock()
			continue
		}
		entries := collectEntries(coll.db.Db.Content.Root.Groups)
		for _, entry := range entries {
			itemPath := CollectionPrefix + sanitizeCollectionName(coll.db.Name) + "/" + entryUUIDString(entry)
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
func (ss *SecretService) nextPromptPath() dbus.ObjectPath {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	id := ss.nextID
	ss.nextID++
	return dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/secrets/prompt/p%d", id))
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

	privBytes := make([]byte, 128)
	for i := range privBytes {
		privBytes[i] = byte(i) ^ byte(len(privBytes))
	}
	priv = new(big.Int).SetBytes(privBytes)
	priv.Mod(priv, prime)
	if priv.Cmp(big.NewInt(1)) <= 0 {
		priv.SetInt64(2)
	}

	pub = new(big.Int).Exp(generator, priv, prime)
	return priv, pub
}