package browser

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// sessionKeys holds the NaCl key pair and shared keys for a single
// browser client connection.
type sessionKeys struct {
	hostPublicKey  *[32]byte
	hostPrivateKey *[32]byte
	clientPublicKey *[32]byte
	sharedSend     *[32]byte // server → client
	sharedRecv     *[32]byte // client → server
	sendNonce      [24]byte
	recvNonce      [24]byte
}

func newSessionKeys() (*sessionKeys, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("browser: generate host key: %w", err)
	}
	return &sessionKeys{
		hostPublicKey:  pub,
		hostPrivateKey: priv,
	}, nil
}

// establish computes the shared key from the client's public key.
// Both directions (send/recv) use the same shared secret because
// Precompute(aPub, bPriv) == Precompute(bPub, aPriv) via DH symmetry.
func (sk *sessionKeys) establish(clientPublicKey *[32]byte) {
	sk.clientPublicKey = clientPublicKey
	shared := new([32]byte)
	box.Precompute(shared, clientPublicKey, sk.hostPrivateKey)
	sk.sharedSend = shared
	sk.sharedRecv = shared
}

// encryptJSON encrypts a JSON value and returns base64 message + current nonce.
// The send nonce is incremented after each call.
func (sk *sessionKeys) encryptJSON(v any) (message, nonce string, err error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", "", err
	}
	encrypted := box.SealAfterPrecomputation(nil, plaintext, &sk.sendNonce, sk.sharedSend)
	nonceStr := base64.StdEncoding.EncodeToString(sk.sendNonce[:])
	incrementNonce(&sk.sendNonce)
	return base64.StdEncoding.EncodeToString(encrypted), nonceStr, nil
}

// decryptMessage decodes and decrypts a base64 message.
// The recv nonce is incremented after each call.
func (sk *sessionKeys) decryptMessage(message string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, fmt.Errorf("browser: base64 decode: %w", err)
	}
	decrypted, ok := box.OpenAfterPrecomputation(nil, ciphertext, &sk.recvNonce, sk.sharedRecv)
	if !ok {
		return nil, fmt.Errorf("browser: decryption failed")
	}
	incrementNonce(&sk.recvNonce)
	return decrypted, nil
}

// incrementNonce increments a 24-byte nonce as a big-endian integer.
func incrementNonce(nonce *[24]byte) {
	for i := 23; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// databaseHash returns the hex hash for a database, matching KeePassXC's format.
// KeePassXC uses the first 4 bytes of SHA256 of the database UUID.
func databaseHash(dbUUID string) string {
	h := sha256.Sum256([]byte(dbUUID))
	return fmt.Sprintf("%x", h[:4])
}
