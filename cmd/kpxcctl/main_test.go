package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/metalgrid/kpxcd/internal/fido2"
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

func TestSelectCandidatesByNumber(t *testing.T) {
	candidates := []candidate{
		{entry: fido2.ImportPasskeyInput{RPID: "a.example.com"}},
		{entry: fido2.ImportPasskeyInput{RPID: "b.example.com"}},
		{entry: fido2.ImportPasskeyInput{RPID: "c.example.com"}},
	}

	picked, err := selectCandidates(candidates, strings.NewReader("2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(picked) != 1 || picked[0].entry.RPID != "b.example.com" {
		t.Fatalf("picked %+v", picked)
	}

	picked, err = selectCandidates(candidates, strings.NewReader("1, 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(picked) != 2 || picked[0].entry.RPID != "a.example.com" || picked[1].entry.RPID != "c.example.com" {
		t.Fatalf("picked %+v", picked)
	}
}

func TestSelectCandidatesAllAndCancel(t *testing.T) {
	candidates := []candidate{
		{entry: fido2.ImportPasskeyInput{RPID: "a.example.com"}},
		{entry: fido2.ImportPasskeyInput{RPID: "b.example.com"}},
	}

	picked, err := selectCandidates(candidates, strings.NewReader("a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(picked) != 2 {
		t.Fatalf("all: picked %+v", picked)
	}

	picked, err = selectCandidates(candidates, strings.NewReader("\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(picked) != 0 {
		t.Fatalf("cancel: picked %+v", picked)
	}
}

func TestSelectCandidatesRejectsBadInput(t *testing.T) {
	candidates := []candidate{{entry: fido2.ImportPasskeyInput{RPID: "a.example.com"}}}
	if _, err := selectCandidates(candidates, strings.NewReader("9\n")); err == nil {
		t.Fatal("out-of-range selection must be refused")
	}
	if _, err := selectCandidates(candidates, strings.NewReader("nope\n")); err == nil {
		t.Fatal("non-numeric selection must be refused")
	}
}

func TestCredentialIDForVaultUUIDShape(t *testing.T) {
	// GitHub's credential ID as Bitwarden exports it: a dashed UUID.
	// The wire bytes are the UUID's 16 hex bytes, NOT the base64 decode
	// of the dashed string (that yields 27 garbage bytes and GitHub
	// rejects the assertion as an unknown credential).
	id := "e318d707-4531-47ca-ba7b-4a22e5bd29ba"
	got, err := credentialIDForVault(id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString("e318d707453147caba7b4a22e5bd29ba")
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(raw)
	if got != want {
		t.Fatalf("UUID credential ID not converted to wire bytes: got %q want %q", got, want)
	}
}

func TestCredentialIDForVaultNonUUIDStaysBase64(t *testing.T) {
	got, err := credentialIDForVault("hhhvuH_j-rF2QBQEndgVLP443V5h9111HqJd0C1gt74")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hhhvuH_j-rF2QBQEndgVLP443V5h9111HqJd0C1gt74" {
		t.Fatalf("genuine base64url IDs must round-trip: %q", got)
	}
}
