//go:build linux

package pamcred

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDerivePAMToken(t *testing.T) {
	got := DerivePAMToken([]byte("login-password"))
	want, err := hex.DecodeString("6746851997ae6dd1b118025baa56753514a2bf21ad02d1f0254bdfbfa9450c74")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DerivePAMToken() = %x, want %x", got, want)
	}
	if len(got) != PAMTokenLen {
		t.Fatalf("len(DerivePAMToken()) = %d, want %d", len(got), PAMTokenLen)
	}
	if bytes.Equal(got, []byte("login-password")) {
		t.Fatal("derived token must not equal the raw password")
	}
}

func TestDerivePAMTokenV2IncludesUID(t *testing.T) {
	first := DerivePAMTokenV2([]byte("login-password"))
	second := DerivePAMTokenV2([]byte("login-password"))
	if !bytes.Equal(first, second) {
		t.Fatal("same password and UID must produce the same V2 token")
	}
	if bytes.Equal(first, DerivePAMToken([]byte("login-password"))) {
		t.Fatal("V2 token must differ from legacy token")
	}
	if len(first) != PAMTokenLen {
		t.Fatalf("len(DerivePAMTokenV2()) = %d, want %d", len(first), PAMTokenLen)
	}
}

func TestDerivePAMTokenDistinctInputs(t *testing.T) {
	first := DerivePAMToken([]byte("login-password"))
	second := DerivePAMToken([]byte("login-password-2"))
	if bytes.Equal(first, second) {
		t.Fatal("different passwords produced the same PAM token")
	}
}

func TestSealOpenIdentity(t *testing.T) {
	token := []byte("login-password")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealIdentity(identity, token)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenIdentity(sealed, token)
	if err != nil {
		t.Fatal(err)
	}
	if opened.String() != identity.String() {
		t.Fatal("opened identity does not match original")
	}
	if _, err := OpenIdentity(sealed, []byte("wrong-password")); err == nil {
		t.Fatal("expected wrong token to fail")
	}
}

func TestSealOpenCredential(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewRandomDBCredential("/tmp/default.kdbx")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealCredential(cred, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenCredential(sealed, identity)
	if err != nil {
		t.Fatal(err)
	}
	if opened.DBPath != cred.DBPath || opened.DBPassword != cred.DBPassword || opened.Version != CredentialVersion {
		t.Fatalf("opened credential mismatch: %#v vs %#v", opened, cred)
	}
}
