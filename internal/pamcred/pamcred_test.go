//go:build linux

package pamcred

import "testing"

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
