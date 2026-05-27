package browser

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestReadMessage(t *testing.T) {
	// Valid message.
	payload := []byte(`{"action":"test"}`)
	buf := make([]byte, 4)
	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	buf[3] = byte(len(payload))
	buf = append(buf, payload...)

	msg, err := readMessage(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("readMessage: %v", err)
	}
	if string(msg) != `{"action":"test"}` {
		t.Fatalf("unexpected message: %s", msg)
	}
}

func TestReadMessage_Empty(t *testing.T) {
	buf := make([]byte, 4)
	_, err := readMessage(bytes.NewReader(buf))
	if err == nil {
		t.Fatal("expected error for zero-length message")
	}
}

func TestReadMessage_TooLarge(t *testing.T) {
	buf := make([]byte, 4)
	buf[0] = 0x80 // length > 1 MiB
	_, err := readMessage(bytes.NewReader(buf))
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
}

func TestWriteMessage(t *testing.T) {
	payload := []byte(`{"action":"test"}`)
	var buf bytes.Buffer
	if err := writeMessage(&buf, payload); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}

	// First 4 bytes should be the length.
	gotLen := int(buf.Bytes()[0])<<24 | int(buf.Bytes()[1])<<16 | int(buf.Bytes()[2])<<8 | int(buf.Bytes()[3])
	if gotLen != len(payload) {
		t.Fatalf("length mismatch: got %d, want %d", gotLen, len(payload))
	}
}

func TestReadWriteRoundTrip(t *testing.T) {
	original := []byte(`{"action":"get-logins","url":"https://example.com"}`)
	var buf bytes.Buffer
	if err := writeMessage(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readMessage(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("round-trip mismatch: got %s, want %s", got, original)
	}
}

func TestSessionKeysEncryptDecrypt(t *testing.T) {
	sk1, err := newSessionKeys()
	if err != nil {
		t.Fatalf("newSessionKeys: %v", err)
	}
	sk2, err := newSessionKeys()
	if err != nil {
		t.Fatalf("newSessionKeys: %v", err)
	}

	// Each side establishes shared keys using the other's public key.
	sk1.establish(sk2.hostPublicKey)
	sk2.establish(sk1.hostPublicKey)

	// sk1 encrypts, sk2 decrypts.
	// Use a map (not []byte) to avoid json.Marshal base64-encoding the value.
	plaintext := map[string]string{"action": "test", "data": "hello"}
	msg, nonce, err := sk1.encryptJSON(plaintext)
	if err != nil {
		t.Fatalf("encryptJSON: %v", err)
	}
	if msg == "" || nonce == "" {
		t.Fatal("empty message or nonce")
	}

	decrypted, err := sk2.decryptMessage(msg)
	if err != nil {
		t.Fatalf("decryptMessage: %v", err)
	}

	// Re-marshal to compare (decryptMessage returns raw JSON bytes).
	expected, _ := json.Marshal(plaintext)
	if string(decrypted) != string(expected) {
		t.Fatalf("round-trip mismatch: got %s, want %s", decrypted, expected)
	}
}

func TestIncrementNonce(t *testing.T) {
	var n [24]byte
	n[23] = 0xFF
	incrementNonce(&n)
	if n[23] != 0 || n[22] != 1 {
		t.Fatalf("expected carry: got %x", n)
	}

	// Full 24-byte carry.
	for i := range n {
		n[i] = 0xFF
	}
	incrementNonce(&n)
	if n[0] != 0 {
		t.Fatalf("expected overflow to zero: got %x", n)
	}
}

func TestDatabaseHash(t *testing.T) {
	h := databaseHash("some-uuid")
	if len(h) != 8 { // 4 bytes = 8 hex chars
		t.Fatalf("expected 8 hex chars, got %d", len(h))
	}
	// Deterministic.
	if databaseHash("some-uuid") != h {
		t.Fatal("non-deterministic")
	}
	// Different input → different output.
	if databaseHash("other-uuid") == h {
		t.Fatal("collision")
	}
}

func TestRandomBytes(t *testing.T) {
	b1, err := randomBytes(32)
	if err != nil {
		t.Fatalf("randomBytes: %v", err)
	}
	if len(b1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b1))
	}
	b2, err := randomBytes(32)
	if err != nil {
		t.Fatalf("randomBytes: %v", err)
	}
	if string(b1) == string(b2) {
		t.Fatal("random bytes should not repeat")
	}
}

func TestRequestUnmarshal(t *testing.T) {
	raw := `{"action":"change-public-keys","publicKey":"dGVzdA==","nonce":"AAAA","clientID":"BBBB"}`
	var req Request
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Action != "change-public-keys" {
		t.Fatalf("action: got %q", req.Action)
	}
}

func TestResponseMarshal(t *testing.T) {
	resp := &Response{
		Action:  "change-public-keys",
		Version: protocolVersion,
		Success: "true",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]string
	json.Unmarshal(data, &m)
	if m["success"] != "true" {
		t.Fatalf("expected success=true, got %s", data)
	}
}

func TestEncryptDecryptInvalidBase64(t *testing.T) {
	sk, _ := newSessionKeys()
	var pub [32]byte
	sk.establish(&pub)
	_, err := sk.decryptMessage("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	sk1, _ := newSessionKeys()
	sk2, _ := newSessionKeys()
	// sk1 establishes with sk2's public key.
	sk1.establish(sk2.hostPublicKey)
	// sk2 establishes with ITS OWN public key (wrong — should be sk1's).
	// This creates a different shared secret.
	sk2.establish(sk2.hostPublicKey)

	msg, _, err := sk1.encryptJSON("test")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = sk2.decryptMessage(msg)
	if err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}
