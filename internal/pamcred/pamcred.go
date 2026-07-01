//go:build linux

// Package pamcred implements the daemon-side credential bootstrap for PAM
// auto-unlock. A short-lived PAM token unwraps an age X25519 identity; that
// identity decrypts the persistent database credential.
package pamcred

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age"
	"github.com/metalgrid/kpxcd/internal/xdg"
	"golang.org/x/crypto/hkdf"
)

const (
	CredentialVersion = 1
	ScryptWorkFactor  = 18
	MaxWorkFactor     = 20

	PAMTokenSalt = "kpxcd-pam-v1"
	PAMTokenLen  = 32
)

// DBCredential is the plaintext payload encrypted to the age X25519 identity.
type DBCredential struct {
	Version    int    `json:"version"`
	DBPath     string `json:"db_path"`
	DBPassword string `json:"db_password"`
	CreatedAt  string `json:"created_at"`
}

// NewRandomDBCredential creates a high-entropy random database password.
func NewRandomDBCredential(dbPath string) (DBCredential, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return DBCredential{}, err
	}
	return DBCredential{
		Version:    CredentialVersion,
		DBPath:     dbPath,
		DBPassword: base64.RawURLEncoding.EncodeToString(secret),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DerivePAMToken derives the legacy kpxcd-specific PAM token from the user's
// login password using HKDF-SHA256. This is the original derivation used for
// all PAM-sealed identities. It is kept unchanged so existing sealed identities
// continue to unlock after a drop-in upgrade.
func DerivePAMToken(password []byte) []byte {
	token := make([]byte, PAMTokenLen)
	r := hkdf.New(sha256.New, password, []byte(PAMTokenSalt), nil)
	if _, err := io.ReadFull(r, token); err != nil {
		// hkdf.Reader never errors on reads <= Expand output length.
		panic(fmt.Sprintf("pamcred: hkdf read failed: %v", err))
	}
	return token
}

// DerivePAMTokenV2 derives a stronger per-user PAM token from the user's login
// password. The salt includes the effective UID so the same password produces
// different tokens for different users and tokens are not portable across
// accounts. This derivation is intended for fresh installations or for an
// explicit migration; it is not used by default because existing sealed
// identities use DerivePAMToken.
func DerivePAMTokenV2(password []byte) []byte {
	token := make([]byte, PAMTokenLen)
	salt := fmt.Sprintf("%s:%d", PAMTokenSalt, os.Getuid())
	r := hkdf.New(sha256.New, password, []byte(salt), nil)
	if _, err := io.ReadFull(r, token); err != nil {
		// hkdf.Reader never errors on reads <= Expand output length.
		panic(fmt.Sprintf("pamcred: hkdf read failed: %v", err))
	}
	return token
}

// GenerateIdentity returns a new age X25519 identity.
func GenerateIdentity() (*age.X25519Identity, error) {
	return age.GenerateX25519Identity()
}

// SealIdentity encrypts an age X25519 private identity using the PAM token as
// an age passphrase recipient.
func SealIdentity(identity *age.X25519Identity, pamToken []byte) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(string(pamToken))
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(ScryptWorkFactor)

	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, identity.String()+"\n"); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// OpenIdentity decrypts and parses an age X25519 private identity using the PAM token.
func OpenIdentity(sealedIdentity, pamToken []byte) (*age.X25519Identity, error) {
	identity, err := age.NewScryptIdentity(string(pamToken))
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(MaxWorkFactor)

	r, err := age.Decrypt(bytes.NewReader(sealedIdentity), identity)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(string(bytes.TrimSpace(plain)))
}

// SealCredential encrypts a database credential to the X25519 recipient.
func SealCredential(cred DBCredential, recipient age.Recipient) ([]byte, error) {
	plain, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// OpenCredential decrypts and validates a database credential using the X25519 identity.
func OpenCredential(sealedCredential []byte, identity age.Identity) (DBCredential, error) {
	r, err := age.Decrypt(bytes.NewReader(sealedCredential), identity)
	if err != nil {
		return DBCredential{}, err
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return DBCredential{}, err
	}
	var cred DBCredential
	if err := json.Unmarshal(plain, &cred); err != nil {
		return DBCredential{}, err
	}
	if cred.Version != CredentialVersion {
		return DBCredential{}, fmt.Errorf("pamcred: unsupported credential version %d", cred.Version)
	}
	if cred.DBPassword == "" || cred.DBPath == "" {
		return DBCredential{}, fmt.Errorf("pamcred: incomplete database credential")
	}
	return cred, nil
}

func WriteSealedIdentity(path string, identity *age.X25519Identity, pamToken []byte) error {
	sealed, err := SealIdentity(identity, pamToken)
	if err != nil {
		return err
	}
	return xdg.WritePrivateFile(path, sealed)
}

func ReadSealedIdentity(path string, pamToken []byte) (*age.X25519Identity, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return OpenIdentity(sealed, pamToken)
}

func WriteSealedCredential(path string, cred DBCredential, recipient age.Recipient) error {
	sealed, err := SealCredential(cred, recipient)
	if err != nil {
		return err
	}
	return xdg.WritePrivateFile(path, sealed)
}

func ReadSealedCredential(path string, identity age.Identity) (DBCredential, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return DBCredential{}, err
	}
	return OpenCredential(sealed, identity)
}
