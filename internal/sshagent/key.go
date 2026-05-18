//go:build linux

package sshagent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Key represents a parsed SSH key with both public and private material.
type Key struct {
	Format        string
	Blob          []byte
	Comment       string
	Signer        ssh.Signer
	IsSecurityKey bool
	SKApplication string
	SKFlags       byte
	SKKeyHandle   []byte
	entryUUID     string
	dbUUID        string
}

// NewKey creates a Key from a crypto.Signer with the given comment.
func NewKey(signer crypto.Signer, comment string) (*Key, error) {
	// Wrap crypto.Signer as ssh.Signer.
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("sshagent: failed to create ssh signer: %w", err)
	}

	pub := sshSigner.PublicKey()
	return &Key{
		Format:  pub.Type(),
		Blob:    pub.Marshal(),
		Comment: comment,
		Signer:  sshSigner,
	}, nil
}

// Fingerprint returns the SHA256 fingerprint in "SHA256:..." format.
func (k *Key) Fingerprint() string {
	if len(k.Blob) == 0 {
		return "SHA256:(empty)"
	}
	h := sha256.Sum256(k.Blob)
	fp := base64.RawStdEncoding.EncodeToString(h[:])
	return "SHA256:" + fp
}

// Equal returns true if k and other have the same fingerprint.
func (k *Key) Equal(other *Key) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.Fingerprint() == other.Fingerprint()
}

// PublicKey returns the ssh.PublicKey for this key.
func (k *Key) PublicKey() ssh.PublicKey {
	pub, err := ssh.ParsePublicKey(k.Blob)
	if err != nil {
		return nil
	}
	return pub
}

// EntryUUID returns the entry UUID.
func (k *Key) EntryUUID() string { return k.entryUUID }

// DBUUID returns the database UUID.
func (k *Key) DBUUID() string { return k.dbUUID }

// SetEntryUUID sets the entry UUID.
func (k *Key) SetEntryUUID(uuid string) { k.entryUUID = uuid }

// SetDBUUID sets the database UUID.
func (k *Key) SetDBUUID(uuid string) { k.dbUUID = uuid }

// SetComment sets the key comment.
func (k *Key) SetComment(c string) { k.Comment = c }

// Sign signs data with this key.
func (k *Key) Sign(data []byte) (*ssh.Signature, error) {
	if k.Signer == nil {
		return nil, fmt.Errorf("sshagent: cannot sign with SK key without security device")
	}
	return k.Signer.Sign(nil, data)
}

// ParsePrivateKey parses an OpenSSH or PEM private key from data.
// Uses golang.org/x/crypto/ssh which handles all formats including bcrypt-pbkdf.
func ParsePrivateKey(data []byte, passphrase string) (*Key, error) {
	var signer ssh.Signer
	var err error

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(data)
	}

	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return parseEncryptedKeyPublicOnly(data)
		}
		return nil, fmt.Errorf("sshagent: failed to parse key: %w", err)
	}

	pub := signer.PublicKey()
	return &Key{
		Format:  pub.Type(),
		Blob:    pub.Marshal(),
		Signer:  signer,
	}, nil
}

// parseEncryptedKeyPublicOnly extracts the public key from an encrypted OpenSSH key.
func parseEncryptedKeyPublicOnly(data []byte) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("sshagent: no OpenSSH private key PEM block found")
	}

	pubBlob := extractPublicBlobFromOpenSSH(block.Bytes)
	if pubBlob == nil {
		return nil, fmt.Errorf("sshagent: failed to extract public key from encrypted key")
	}

	pub, err := ssh.ParsePublicKey(pubBlob)
	if err != nil {
		return nil, fmt.Errorf("sshagent: failed to parse public key: %w", err)
	}

	return &Key{
		Format: pub.Type(),
		Blob:   pub.Marshal(),
	}, nil
}

// extractPublicBlobFromOpenSSH extracts the public key blob from an openssh-key-v1 block.
func extractPublicBlobFromOpenSSH(raw []byte) []byte {
	magic := "openssh-key-v1\x00"
	if len(raw) < len(magic) || string(raw[:len(magic)]) != magic {
		return nil
	}

	pos := len(magic)
	// Skip cipher name, kdf name, kdf options.
	for i := 0; i < 3; i++ {
		_, rest := readSSHStringFrom(raw[pos:])
		if rest == nil {
			return nil
		}
		pos = len(raw) - len(rest)
	}
	// Skip numKeys (4 bytes).
	if len(raw)-pos < 4 {
		return nil
	}
	pos += 4

	// First public key blob.
	pubBlob, _ := readSSHStringFrom(raw[pos:])
	return pubBlob
}

// readSSHStringFrom reads an SSH wire-format string.
func readSSHStringFrom(data []byte) ([]byte, []byte) {
	if len(data) < 4 {
		return nil, nil
	}
	length := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	data = data[4:]
	if len(data) < length {
		return nil, nil
	}
	return data[:length], data[length:]
}

// GenerateTestKey generates a test key of the specified type.
func GenerateTestKey(keyType string) (*Key, error) {
	var priv crypto.Signer
	var err error

	switch keyType {
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa-p256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ecdsa-p521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("sshagent: unsupported test key type: %s", keyType)
	}
	if err != nil {
		return nil, err
	}

	return NewKey(priv, "test@"+keyType)
}

// encodeECDSAPrivateKey encodes an ECDSA private key as PEM.
func encodeECDSAPrivateKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return "-----BEGIN EC PRIVATE KEY-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END EC PRIVATE KEY-----", nil
}

// encodeEd25519PrivateKey encodes an Ed25519 private key as PEM.
func encodeEd25519PrivateKey(key ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return "-----BEGIN PRIVATE KEY-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END PRIVATE KEY-----", nil
}