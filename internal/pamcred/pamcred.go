//go:build linux

// Package pamcred implements the daemon-side credential bootstrap for PAM
// auto-unlock. A short-lived PAM token unwraps an age X25519 identity; that
// identity decrypts the persistent database credential.
package pamcred

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age"
	"github.com/user/kpxcd/internal/xdg"
)

const (
	CredentialVersion = 1
	ScryptWorkFactor  = 18
	MaxWorkFactor     = 20
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
