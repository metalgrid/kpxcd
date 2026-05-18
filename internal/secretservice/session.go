//go:build linux

package secretservice

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// Session implements org.freedesktop.Secret.Session.
// It holds the negotiated encryption key for transferring secrets over DBus.
type Session struct {
	conn   *dbus.Conn
	path   dbus.ObjectPath
	alg    string       // "plain" or "dh-ietf1024-sha256-aes128-cbc"
	key    []byte       // AES key (for encrypted sessions)
	closed bool
}

// NewPlainSession creates a session with no encryption (for testing or
// when the client requests "plain" algorithm).
func NewPlainSession(conn *dbus.Conn, path dbus.ObjectPath) *Session {
	return &Session{
		conn: conn,
		path: path,
		alg:  "plain",
	}
}

// NewEncryptedSession creates a session using AES-CBC with the given key.
// The key is a 16-byte (128-bit) AES key.
func NewEncryptedSession(conn *dbus.Conn, path dbus.ObjectPath, key []byte) *Session {
	return &Session{
		conn: conn,
		path: path,
		alg:  "dh-ietf1024-sha256-aes128-cbc",
		key:  key,
	}
}

// Path returns the DBus object path of this session.
func (s *Session) Path() dbus.ObjectPath {
	return s.path
}

// Algorithm returns the negotiated algorithm.
func (s *Session) Algorithm() string {
	return s.alg
}

// Close closes the session, invalidating it.
func (s *Session) Close() *dbus.Error {
	s.closed = true
	return nil
}

// Encrypt encrypts the given plaintext using AES-CBC with the session key.
// Returns (iv, ciphertext, error). The IV is prepended to the ciphertext.
func (s *Session) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	if s.alg == "plain" {
		// No encryption: return empty IV and plaintext as-is.
		return nil, plaintext, nil
	}
	if len(s.key) == 0 {
		return nil, nil, fmt.Errorf("secretservice: no encryption key for session %s", s.path)
	}
	if s.closed {
		return nil, nil, fmt.Errorf("secretservice: session %s is closed", s.path)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, nil, fmt.Errorf("secretservice: create cipher: %w", err)
	}

	// Generate a random IV.
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("secretservice: generate IV: %w", err)
	}

	// Pad the plaintext to a multiple of the block size (PKCS#7).
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt using CBC mode.
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return iv, ciphertext, nil
}

// Decrypt decrypts the given ciphertext using AES-CBC with the session key.
func (s *Session) Decrypt(iv, ciphertext []byte) ([]byte, error) {
	if s.alg == "plain" {
		return ciphertext, nil
	}
	if len(s.key) == 0 {
		return nil, fmt.Errorf("secretservice: no encryption key for session %s", s.path)
	}
	if s.closed {
		return nil, fmt.Errorf("secretservice: session %s is closed", s.path)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("secretservice: create cipher: %w", err)
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("secretservice: invalid ciphertext length")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding.
	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("secretservice: unpad: %w", err)
	}

	return plaintext, nil
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}
	return data[:len(data)-padLen], nil
}

// DeriveSessionKey derives a shared AES key from a DH shared secret
// using HKDF-SHA256 per RFC 5869, as required by the Secret Service spec
// for the "dh-ietf1024-sha256-aes128-cbc-pkcs7" algorithm.
//
//   salt = empty (0x00 * HashLen)
//   info = empty string
//   hash = SHA-256
//
// PRK  = HMAC-SHA256(salt, sharedSecret)
// OKM  = HMAC-SHA256(PRK, 0x01)
// key  = OKM[:16]  (AES-128)
func DeriveSessionKey(sharedSecret []byte) []byte {
	// HKDF-Extract: PRK = HMAC-SHA256(salt=zeros, IKM=sharedSecret)
	salt := make([]byte, sha256.Size)
	prk := hmac.New(sha256.New, salt)
	prk.Write(sharedSecret)
	prkBytes := prk.Sum(nil)

	// HKDF-Expand: T1 = HMAC-SHA256(PRK, info || 0x01)
	// info is empty, so just append counter byte 0x01.
	expand := hmac.New(sha256.New, prkBytes)
	expand.Write([]byte{0x01})
	okm := expand.Sum(nil)

	return okm[:16] // AES-128 key
}
