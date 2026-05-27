//go:build linux

// Package browser implements the KeePassXC browser extension protocol.
// The extension communicates via keepassxc-proxy over a Unix domain socket
// using NaCl-encrypted JSON messages.
package browser

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/tobischo/gokeepasslib/v3"
)

// Server listens on the KeePassXC browser socket and dispatches protocol
// messages to handlers.
type Server struct {
	config     *config.BrowserConfig
	pool       *dbpool.DatabasePool
	listener   net.Listener
	socketPath string
	mu         sync.Mutex
	done       chan struct{}
}

// NewServer creates a new browser extension protocol server.
func NewServer(cfg *config.BrowserConfig, pool *dbpool.DatabasePool, socketPath string) *Server {
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}
	return &Server{
		config:     cfg,
		pool:       pool,
		socketPath: socketPath,
		done:       make(chan struct{}),
	}
}

// Listen starts listening on the Unix domain socket.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("browser: failed to create socket directory: %w", err)
	}

	// Remove stale socket.
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("browser: failed to listen on %s: %w", s.socketPath, err)
	}
	s.listener = ln
	return nil
}

// Serve accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.done:
			return nil
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.done:
				return nil
			default:
				slog.Warn("browser: accept error", "error", err)
				continue
			}
		}

		go s.handleConn(ctx, conn)
	}
}

// Close shuts down the server and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	close(s.done)
	var err error
	if s.listener != nil {
		err = s.listener.Close()
		s.listener = nil
	}
	os.Remove(s.socketPath)
	return err
}

// SocketPath returns the resolved socket path.
func (s *Server) SocketPath() string {
	return s.socketPath
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	slog.Debug("browser: new connection", "remote", conn.RemoteAddr())

	var keys *sessionKeys

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		raw, err := readMessage(conn)
		if err != nil {
			slog.Debug("browser: read error, closing connection", "error", err)
			return
		}

		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			slog.Warn("browser: invalid JSON from client", "error", err)
			return
		}

		resp := s.dispatch(&req, keys)
		if resp == nil {
			return
		}

		// change-public-keys establishes the session; all other encrypted
		// actions need the session keys.
		if req.Action == "change-public-keys" {
			newKeys, pkResp := s.handleChangePublicKeys(&req)
			if pkResp == nil {
				return
			}
			keys = newKeys
			resp = pkResp
		}

		if err := encodeResponse(conn, resp); err != nil {
			slog.Warn("browser: write error", "error", err)
			return
		}
	}
}

// dispatch routes an action to its handler. Returns nil if the connection
// should be closed.
func (s *Server) dispatch(req *Request, keys *sessionKeys) *Response {
	switch req.Action {
	case "change-public-keys":
		// Handled separately in handleConn because it mutates session state.
		return &Response{Success: "false", Error: "unexpected change-public-keys"}
	case "get-databasehash":
		return s.handleGetDatabaseHash(keys, req)
	case "test-associate":
		return s.handleTestAssociate(keys, req)
	case "associate":
		return s.handleAssociate(keys, req)
	case "get-logins":
		return s.handleGetLogins(keys, req)
	case "set-login":
		return s.handleSetLogin(keys, req)
	case "lock-database":
		return s.handleLockDatabase(keys, req)
	case "get-totp":
		return s.handleGetTotp(keys, req)
	case "generate-password":
		return s.handleGeneratePassword(req)
	case "get-database-groups":
		return s.handleGetDatabaseGroups(keys, req)
	case "create-new-group":
		return s.handleCreateNewGroup(keys, req)
	default:
		slog.Warn("browser: unknown action", "action", req.Action)
		return &Response{Success: "false", Error: fmt.Sprintf("unknown action: %s", req.Action)}
	}
}

func (s *Server) handleChangePublicKeys(req *Request) (*sessionKeys, *Response) {
	clientPubB64 := req.PublicKey
	if clientPubB64 == "" {
		return nil, &Response{Action: "change-public-keys", Success: "false", Error: "missing publicKey"}
	}

	clientPubSlice, err := base64.StdEncoding.DecodeString(clientPubB64)
	if err != nil || len(clientPubSlice) != 32 {
		return nil, &Response{Action: "change-public-keys", Success: "false", Error: "invalid publicKey"}
	}

	keys, err := newSessionKeys()
	if err != nil {
		return nil, &Response{Action: "change-public-keys", Success: "false", Error: "key generation failed"}
	}

	var clientPub [32]byte
	copy(clientPub[:], clientPubSlice)
	keys.establish(&clientPub)

	return keys, &Response{
		Action:    "change-public-keys",
		Version:   protocolVersion,
		PublicKey: base64.StdEncoding.EncodeToString(keys.hostPublicKey[:]),
		Success:   "true",
	}
}

func (s *Server) handleGetDatabaseHash(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}

	dbs := s.pool.List()
	if len(dbs) == 0 {
		return encryptedError(keys, "no database open")
	}

	var db *dbpool.OpenDatabase
	for _, d := range dbs {
		if !d.Locked {
			db = d
			break
		}
	}
	if db == nil {
		return encryptedError(keys, "database is locked")
	}

	hash := databaseHash(db.UUID)

	inner := map[string]string{
		"hash":    hash,
		"version": protocolVersion,
		"success": "true",
	}

	msg, nonce, err := keys.encryptJSON(inner)
	if err != nil {
		return encryptedError(keys, "encryption failed")
	}

	return &Response{
		Action:  "database-hash",
		Message: msg,
		Nonce:   nonce,
		Success: "true",
	}
}

func (s *Server) handleTestAssociate(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}

	decrypted, err := keys.decryptMessage(req.Message)
	if err != nil {
		return encryptedError(keys, "decryption failed")
	}

	var inner struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(decrypted, &inner); err != nil {
		return encryptedError(keys, "invalid message")
	}

	dbUUID, err := findAssociation(s.pool, inner.Key)
	if err != nil {
		return encryptedError(keys, "association not found")
	}

	hash := databaseHash(dbUUID)
	resp := map[string]string{
		"id":      inner.ID,
		"hash":    hash,
		"version": protocolVersion,
		"success": "true",
	}

	msg, nonce, err := keys.encryptJSON(resp)
	if err != nil {
		return encryptedError(keys, "encryption failed")
	}

	return &Response{
		Message: msg,
		Nonce:   nonce,
		Success: "true",
		Hash:    hash,
	}
}

func (s *Server) handleAssociate(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}

	decrypted, err := keys.decryptMessage(req.Message)
	if err != nil {
		return encryptedError(keys, "decryption failed")
	}

	var inner struct {
		Key   string `json:"key"`
		IDKey string `json:"idKey"`
	}
	if err := json.Unmarshal(decrypted, &inner); err != nil {
		return encryptedError(keys, "invalid message")
	}

	dbs := s.pool.List()
	var db *dbpool.OpenDatabase
	for _, d := range dbs {
		if !d.Locked {
			db = d
			break
		}
	}
	if db == nil {
		return encryptedError(keys, "no database open")
	}

	assocID, err := generateAssociationID()
	if err != nil {
		return encryptedError(keys, "failed to generate association ID")
	}

	if err := storeAssociation(s.pool, db.UUID, assocID, inner.IDKey); err != nil {
		return encryptedError(keys, err.Error())
	}

	hash := databaseHash(db.UUID)
	resp := map[string]string{
		"id":      assocID,
		"hash":    hash,
		"version": protocolVersion,
		"success": "true",
	}

	msg, nonce, err := keys.encryptJSON(resp)
	if err != nil {
		return encryptedError(keys, "encryption failed")
	}

	return &Response{
		Message: msg,
		Nonce:   nonce,
		Success: "true",
		Hash:    hash,
		ID:      assocID,
	}
}

func (s *Server) handleGetLogins(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}

	decrypted, err := keys.decryptMessage(req.Message)
	if err != nil {
		return encryptedError(keys, "decryption failed")
	}

	var inner struct {
		URL       string `json:"url"`
		SubmitURL string `json:"submitUrl"`
		HTTPAuth  string `json:"httpAuth"`
		Keys      []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(decrypted, &inner); err != nil {
		return encryptedError(keys, "invalid message")
	}

	searchURL := inner.URL
	if inner.SubmitURL != "" {
		searchURL = inner.SubmitURL
	}

	// Search all unlocked databases for matching entries.
	type loginEntry struct {
		Login    string `json:"login"`
		Name     string `json:"name"`
		Password string `json:"password"`
		UUID     string `json:"uuid"`
		Expired  string `json:"expired,omitempty"`
	}

	var entries []loginEntry
	dbs := s.pool.List()
	for _, db := range dbs {
		if db.Locked {
			continue
		}

		// Verify the database hash matches one of the provided keys.
		hash := databaseHash(db.UUID)
		hashMatched := len(inner.Keys) == 0
		for _, k := range inner.Keys {
			if k.ID != "" && k.ID == hash {
				hashMatched = true
				break
			}
		}
		if !hashMatched {
			continue
		}

		db.RLock()
		allEntries := db.RootEntries()
		db.RUnlock()

		for i := range allEntries {
			e := &allEntries[i]
			entryURL := e.GetContent("URL")
			if !matchURL(entryURL, searchURL) {
				continue
			}

			// Skip the browser settings entry itself.
			if e.GetTitle() == browserSettingsKey {
				continue
			}

			login := e.GetContent("UserName")
			name := e.GetTitle()
			password := e.GetContent("Password")
			uuid := fmt.Sprintf("%x", e.UUID[:])

			entries = append(entries, loginEntry{
				Login:    login,
				Name:     name,
				Password: password,
				UUID:     uuid,
			})
		}
	}

	if entries == nil {
		entries = []loginEntry{}
	}

	dbs2 := s.pool.List()
	var activeDB *dbpool.OpenDatabase
	for _, d := range dbs2 {
		if !d.Locked {
			activeDB = d
			break
		}
	}
	activeHash := ""
	if activeDB != nil {
		activeHash = databaseHash(activeDB.UUID)
	}

	resp := map[string]interface{}{
		"count":   fmt.Sprintf("%d", len(entries)),
		"entries": entries,
		"success": "true",
		"version": protocolVersion,
		"hash":    activeHash,
	}

	msg, nonce, err := keys.encryptJSON(resp)
	if err != nil {
		return encryptedError(keys, "encryption failed")
	}

	return &Response{
		Message: msg,
		Nonce:   nonce,
		Success: "true",
		Hash:    activeHash,
		Count:   fmt.Sprintf("%d", len(entries)),
	}
}

func (s *Server) handleSetLogin(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}
	return errorResponse("not yet implemented")
}

func (s *Server) handleLockDatabase(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}
	return errorResponse("not yet implemented")
}

func (s *Server) handleGetTotp(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}
	// get-totp is sent unencrypted: {"action":"get-totp","uuid":"<uuid>"}
	// Requires adding UUID to Request struct.
	return errorResponse("not yet implemented")
}

func (s *Server) handleGeneratePassword(req *Request) *Response {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	const length = 20
	password, err := generatePassword(charset, length)
	if err != nil {
		return &Response{Success: "false", Error: "generation failed", Version: protocolVersion}
	}
	return &Response{Version: protocolVersion, Password: password, Success: "true"}
}

func (s *Server) handleGetDatabaseGroups(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}

	dbs := s.pool.List()
	var db *dbpool.OpenDatabase
	for _, d := range dbs {
		if !d.Locked {
			db = d
			break
		}
	}
	if db == nil {
		return encryptedError(keys, "no database open")
	}

	db.RLock()
	groups := serializeGroups(db.Db.Content.Root.Groups)
	db.RUnlock()

	defaultGroup := browserGroupName
	_, g, _ := findBrowserGroup(s.pool)
	if g == nil {
		defaultGroup = ""
	}

	resp := map[string]interface{}{
		"defaultGroup": defaultGroup, "groups": groups,
		"success": "true", "version": protocolVersion,
	}
	msg, nonce, err := keys.encryptJSON(resp)
	if err != nil {
		return encryptedError(keys, "encryption failed")
	}
	return &Response{Message: msg, Nonce: nonce, Success: "true"}
}

func (s *Server) handleCreateNewGroup(keys *sessionKeys, req *Request) *Response {
	if keys == nil {
		return errorResponse("not associated")
	}

	decrypted, err := keys.decryptMessage(req.Message)
	if err != nil {
		return encryptedError(keys, "decryption failed")
	}

	var inner struct {
		GroupName string `json:"groupName"`
	}
	if err := json.Unmarshal(decrypted, &inner); err != nil {
		return encryptedError(keys, "invalid message")
	}

	dbs := s.pool.List()
	var db *dbpool.OpenDatabase
	for _, d := range dbs {
		if !d.Locked {
			db = d
			break
		}
	}
	if db == nil {
		return encryptedError(keys, "no database open")
	}

	var groupUUID string
	err = db.UpdateAndSave(func(kdb *gokeepasslib.Database) error {
		if kdb.Content == nil || kdb.Content.Root == nil || len(kdb.Content.Root.Groups) == 0 {
			return fmt.Errorf("database has no root group")
		}
		group := findOrCreateGroup(&kdb.Content.Root.Groups[0], inner.GroupName)
		groupUUID = fmt.Sprintf("%x", group.UUID[:])
		return nil
	})
	if err != nil {
		return encryptedError(keys, err.Error())
	}

	resp := map[string]string{"name": inner.GroupName, "uuid": groupUUID, "success": "true"}
	msg, nonce, err2 := keys.encryptJSON(resp)
	if err2 != nil {
		return encryptedError(keys, "encryption failed")
	}
	return &Response{Message: msg, Nonce: nonce, Success: "true"}
}

func errorResponse(msg string) *Response {
	return &Response{Success: "false", Error: msg}
}

func encryptedError(keys *sessionKeys, msg string) *Response {
	inner := map[string]string{
		"success": "false",
		"error":   msg,
		"version": protocolVersion,
	}
	msg2, nonce, err := keys.encryptJSON(inner)
	if err != nil {
		// If encryption fails, return unencrypted error.
		return errorResponse(msg)
	}
	return &Response{Message: msg2, Nonce: nonce, Success: "false", Error: msg}
}

func defaultSocketPath() string {
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		xdg = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	return filepath.Join(xdg, "app/org.keepassxc.KeePassXC", "browser.sock")
}

func init() {
	// Ensure rand.Reader is available.
	_ = rand.Reader
}
