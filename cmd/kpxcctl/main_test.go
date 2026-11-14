package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// Bitwarden exports fido2Credentials keyValue as base64url (dashes and
// underscores, unpadded). The parser must accept all three base64 shapes
// and round-trip the decoded DER PKCS#8 key back out as PEM.
func TestParseBitwardenCredentialDecodesBase64URLKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	std := base64.StdEncoding.EncodeToString(der)
	base64URL := strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(std)

	credID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 16))
	handle := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4})
	cred := bitwardenFido2Credential{
		KeyType:      "public-key",
		KeyAlgorithm: "ECDSA",
		KeyCurve:     "P-256",
		CredentialID: credID,
		KeyValue:     base64URL,
		RPID:         "example.com",
		UserHandle:   handle,
		UserName:     "user",
		Counter:      "7",
	}

	in, err := parseBitwardenCredential(cred)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	block, _ := pem.Decode([]byte(in.PrivateKeyPEM))
	if block == nil {
		t.Fatal("PrivateKeyPEM is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("PEM does not carry PKCS#8 DER: %v", err)
	}
	pk := parsed.(*ecdsa.PrivateKey)
	if pk.PublicKey.X.Cmp(key.X) != 0 || pk.PublicKey.Y.Cmp(key.Y) != 0 {
		t.Fatal("decoded key differs from the exported key")
	}
	if in.CredentialID != credID || in.UserHandle != handle {
		t.Fatalf("canonical base64url must round-trip: %q %q", in.CredentialID, in.UserHandle)
	}
	if in.SignCount != 7 {
		t.Fatalf("sign count not carried: %d", in.SignCount)
	}
}

func TestParseBitwardenCredentialRejectsNonP256(t *testing.T) {
	cred := bitwardenFido2Credential{
		KeyType:      "public-key",
		KeyAlgorithm: "RSA",
		KeyCurve:     "",
		KeyValue:     "AAAA",
		RPID:         "example.com",
		CredentialID: "aa",
		UserHandle:   "aa",
	}
	if _, err := parseBitwardenCredential(cred); err == nil {
		t.Fatal("non-ECDSA-P-256 keys must be refused")
	}
}

func TestParseBitwardenCredentialDecodesStandardPaddedKey(t *testing.T) {
	// The decoder only handles base64 here; DER validity is checked by
	// the daemon at import time.
	cred := bitwardenFido2Credential{
		KeyType:      "public-key",
		KeyAlgorithm: "ECDSA",
		KeyCurve:     "P-256",
		KeyValue:     base64.StdEncoding.EncodeToString([]byte{4, 2, 1, 2}),
		RPID:         "example.com",
		CredentialID: "aa",
		UserHandle:   "aa",
	}
	if _, err := parseBitwardenCredential(cred); err != nil {
		t.Fatalf("standard padded base64 must decode: %v", err)
	}
}

func bigIntDER() []byte {
	// Minimal deterministic non-empty DER for base64 fixtures only.
	return []byte{0x04, 0x02, 0x01, 0x02}
}
