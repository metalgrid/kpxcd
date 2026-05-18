//go:build linux

package secretservice

import (
	"bytes"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	"github.com/user/kpxcd/internal/dbpool"
)

// TestPKCS7Padding verifies PKCS#7 padding and unpadding.
func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		expected  []byte
	}{
		{
			name:      "exact block size",
			data:      []byte("1234567890123456"),
			blockSize: 16,
			expected:  append([]byte("1234567890123456"), bytes.Repeat([]byte{0x10}, 16)...),
		},
		{
			name:      "one byte short",
			data:      []byte("123456789012345"),
			blockSize: 16,
			expected:  append([]byte("123456789012345"), 0x01),
		},
		{
			name:      "empty data",
			data:      []byte{},
			blockSize: 16,
			expected:  bytes.Repeat([]byte{0x10}, 16),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs7Pad(tc.data, tc.blockSize)
			if !bytes.Equal(padded, tc.expected) {
				t.Errorf("pkcs7Pad(%q, %d) = %v, want %v", tc.data, tc.blockSize, padded, tc.expected)
			}

			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("pkcs7Unpad failed: %v", err)
			}
			if !bytes.Equal(unpadded, tc.data) {
				t.Errorf("pkcs7Unpad result = %v, want %v", unpadded, tc.data)
			}
		})
	}
}

// TestSessionEncryptDecryptPlain verifies plain (no encryption) sessions.
func TestSessionEncryptDecryptPlain(t *testing.T) {
	sess := NewPlainSession(nil, "/test/session/plain")

	plaintext := []byte("secret password")
	iv, ciphertext, err := sess.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if iv != nil {
		t.Error("expected nil IV for plain session")
	}
	if !bytes.Equal(ciphertext, plaintext) {
		t.Errorf("plain session ciphertext should equal plaintext")
	}

	// Decrypt should also work.
	decrypted, err := sess.Decrypt(iv, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestSessionEncryptDecryptEncrypted verifies AES-CBC encrypted sessions.
func TestSessionEncryptDecryptEncrypted(t *testing.T) {
	// Create a 16-byte key.
	key := []byte("0123456789abcdef")
	sess := NewEncryptedSession(nil, "/test/session/enc", key)

	plaintext := []byte("secret password 123")
	iv, ciphertext, err := sess.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(iv) != 16 {
		t.Errorf("expected 16-byte IV, got %d", len(iv))
	}
	if len(ciphertext) == 0 || len(ciphertext)%16 != 0 {
		t.Errorf("ciphertext length %d should be multiple of 16", len(ciphertext))
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("encrypted ciphertext should not equal plaintext")
	}

	// Decrypt.
	decrypted, err := sess.Decrypt(iv, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestSessionClose verifies that closed sessions reject operations.
func TestSessionClose(t *testing.T) {
	key := []byte("0123456789abcdef")
	sess := NewEncryptedSession(nil, "/test/session/close", key)

	sess.Close()

	_, _, err := sess.Encrypt([]byte("test"))
	if err == nil {
		t.Error("expected error when encrypting with closed session")
	}
}

// TestDeriveSessionKey verifies key derivation.
func TestDeriveSessionKey(t *testing.T) {
	secret := []byte("shared secret data for testing")
	key := DeriveSessionKey(secret)
	if len(key) != 16 {
		t.Errorf("expected 16-byte key, got %d", len(key))
	}

	// Same input should produce same key.
	key2 := DeriveSessionKey(secret)
	if !bytes.Equal(key, key2) {
		t.Error("same secret should produce same key")
	}

	// Different input should produce different key.
	differentSecret := []byte("different secret data")
	key3 := DeriveSessionKey(differentSecret)
	if bytes.Equal(key, key3) {
		t.Error("different secrets should produce different keys")
	}
}

// newTestOpenDatabase creates a minimal *dbpool.OpenDatabase for testing.
func newTestOpenDatabase(name, uuid string, locked bool) *dbpool.OpenDatabase {
	return &dbpool.OpenDatabase{
		Name:   name,
		UUID:   uuid,
		Locked: locked,
	}
}

// TestEntryAttributes verifies attribute mapping from KeePass entries.
func TestEntryAttributes(t *testing.T) {
	entry := gokeepasslib.Entry{
		UUID: gokeepasslib.UUID{},
		Times: gokeepasslib.TimeData{
			CreationTime:         &wrappers.TimeWrapper{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
			LastModificationTime: &wrappers.TimeWrapper{Time: time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)},
		},
		Values: []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: "My Bank Account"}},
			{Key: "UserName", Value: gokeepasslib.V{Content: "johndoe"}},
			{Key: "Password", Value: gokeepasslib.V{Content: "s3cret!", Protected: wrappers.BoolWrapper{Bool: true}}},
			{Key: "URL", Value: gokeepasslib.V{Content: "https://bank.example.com"}},
			{Key: "Notes", Value: gokeepasslib.V{Content: "Primary savings account\nPIN: 1234"}},
			{Key: "CustomField", Value: gokeepasslib.V{Content: "custom_value"}},
		},
	}

	odb := newTestOpenDatabase("Personal.kdbx", "test-db-uuid-1234", false)

	attrs := EntryAttributes(odb, entry)

	// Check standard attributes.
	if attrs[AttrTitle] != "My Bank Account" {
		t.Errorf("title = %q, want %q", attrs[AttrTitle], "My Bank Account")
	}
	if attrs[AttrUserName] != "johndoe" {
		t.Errorf("username = %q, want %q", attrs[AttrUserName], "johndoe")
	}
	if attrs[AttrURL] != "https://bank.example.com" {
		t.Errorf("URL = %q, want %q", attrs[AttrURL], "https://bank.example.com")
	}
	// Notes should be first line only.
	if attrs[AttrNotes] != "Primary savings account" {
		t.Errorf("notes = %q, want %q", attrs[AttrNotes], "Primary savings account")
	}
	if attrs[AttrDBNamePrefix] != "Personal.kdbx" {
		t.Errorf("dbname = %q, want %q", attrs[AttrDBNamePrefix], "Personal.kdbx")
	}
	if attrs[AttrDBUUIDPrefix] != "test-db-uuid-1234" {
		t.Errorf("dbuuid = %q, want %q", attrs[AttrDBUUIDPrefix], "test-db-uuid-1234")
	}
	if attrs["custom:CustomField"] != "custom_value" {
		t.Errorf("custom field = %q, want %q", attrs["custom:CustomField"], "custom_value")
	}
}

// TestMatchAttributes verifies attribute matching logic.
func TestMatchAttributes(t *testing.T) {
	entry := gokeepasslib.Entry{
		Values: []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: "GitHub"}},
			{Key: "UserName", Value: gokeepasslib.V{Content: "dev@example.com"}},
			{Key: "URL", Value: gokeepasslib.V{Content: "https://github.com/user/repo"}},
			{Key: "Notes", Value: gokeepasslib.V{Content: "Work repository"}},
			{Key: "CustomAttr", Value: gokeepasslib.V{Content: "custom_val"}},
		},
	}

	odb := newTestOpenDatabase("Work.kdbx", "work-uuid", false)

	tests := []struct {
		name      string
		attributes map[string]string
		wantMatch bool
	}{
		{
			name:      "match by title",
			attributes: map[string]string{AttrTitle: "GitHub"},
			wantMatch: true,
		},
		{
			name:      "match by username",
			attributes: map[string]string{AttrUserName: "dev@example.com"},
			wantMatch: true,
		},
		{
			name:      "match by URL",
			attributes: map[string]string{AttrURL: "https://github.com/user/repo"},
			wantMatch: true,
		},
		{
			name:      "partial URL match",
			attributes: map[string]string{AttrURL: "github.com"},
			wantMatch: true,
		},
		{
			name:      "match by database name",
			attributes: map[string]string{AttrDBNamePrefix: "Work.kdbx"},
			wantMatch: true,
		},
		{
			name:      "match by custom attribute",
			attributes: map[string]string{"custom:CustomAttr": "custom_val"},
			wantMatch: true,
		},
		{
			name:      "non-matching title",
			attributes: map[string]string{AttrTitle: "GitLab"},
			wantMatch: false,
		},
		{
			name:      "non-matching username",
			attributes: map[string]string{AttrUserName: "admin@test.com"},
			wantMatch: false,
		},
		{
			name:      "multiple matching attributes",
			attributes: map[string]string{AttrTitle: "GitHub", AttrUserName: "dev@example.com"},
			wantMatch: true,
		},
		{
			name:      "one matching one not",
			attributes: map[string]string{AttrTitle: "GitHub", AttrUserName: "nobody@test.com"},
			wantMatch: false,
		},
		{
			name:      "empty attributes",
			attributes: map[string]string{},
			wantMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchAttributes(entry, odb, tc.attributes)
			if got != tc.wantMatch {
				t.Errorf("MatchAttributes() = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

// TestSanitizeCollectionName verifies path-safe name sanitization.
func TestSanitizeCollectionName(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"Personal", "Personal"},
		{"Work.kdbx", "Work.kdbx"},
		{"my database", "my_database"},
		{"special!@#$%", "special_____"},
		{"path/to/file", "path_to_file"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := sanitizeCollectionName(tc.input)
			if got != tc.expect {
				t.Errorf("sanitizeCollectionName(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

// TestCollectEntries verifies recursive entry collection from groups.
func TestCollectEntries(t *testing.T) {
	groups := []gokeepasslib.Group{
		{
			Name: "Root",
			Entries: []gokeepasslib.Entry{
				{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Entry 1"}}}},
				{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Entry 2"}}}},
			},
			Groups: []gokeepasslib.Group{
				{
					Name: "SubGroup",
					Entries: []gokeepasslib.Entry{
						{Values: []gokeepasslib.ValueData{{Key: "Title", Value: gokeepasslib.V{Content: "Entry 3"}}}},
					},
				},
			},
		},
	}

	entries := collectEntries(groups)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	titles := make(map[string]bool)
	for _, e := range entries {
		titles[e.GetTitle()] = true
	}

	for _, expected := range []string{"Entry 1", "Entry 2", "Entry 3"} {
		if !titles[expected] {
			t.Errorf("missing entry with title %q", expected)
		}
	}
}

// TestEntryUUIDString verifies UUID string conversion.
func TestEntryUUIDString(t *testing.T) {
	uuidBytes := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	uuid := gokeepasslib.UUID{}
	copy(uuid[:], uuidBytes[:])

	entry := gokeepasslib.Entry{UUID: uuid}
	result := entryUUIDString(entry)

	if result == "" {
		t.Error("entryUUIDString returned empty string")
	}
}

// TestPrompt verifies that a prompt can be created and auto-accepts.
func TestPrompt(t *testing.T) {
	// We cannot test with a real DBus connection, but we can verify
	// the struct and channel behavior.
	// The prompt should create without panicking.
	p := NewPrompt(nil, "/test/prompt/1")
	if p == nil {
		t.Fatal("NewPrompt returned nil")
	}
	if p.Path() != "/test/prompt/1" {
		t.Errorf("path = %q, want %q", p.Path(), "/test/prompt/1")
	}

	// Prompt() with nil conn will just signal completion.
	// This should not panic.
	p.Prompt()

	// Done channel should be closed after Prompt().
	select {
	case <-p.Done():
		// Success.
	default:
		// Prompt is async, give it a moment.
		time.Sleep(10 * time.Millisecond)
		select {
		case <-p.Done():
			// Success.
		default:
			t.Error("Done() channel was not closed after Prompt()")
		}
	}
}

// TestItemProperties verifies Item field accessors.
func TestItemProperties(t *testing.T) {
	entry := gokeepasslib.Entry{
		UUID: gokeepasslib.UUID{},
		Times: gokeepasslib.TimeData{
			CreationTime:         &wrappers.TimeWrapper{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
			LastModificationTime: &wrappers.TimeWrapper{Time: time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)},
		},
		Values: []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: "Test Entry"}},
			{Key: "UserName", Value: gokeepasslib.V{Content: "testuser"}},
			{Key: "Password", Value: gokeepasslib.V{Content: "testpass", Protected: wrappers.BoolWrapper{Bool: true}}},
			{Key: "URL", Value: gokeepasslib.V{Content: "https://example.com"}},
		},
	}

	// Create a minimal real OpenDatabase for testing.
	odb := newTestOpenDatabase("Test.kdbx", "test-uuid", false)

	coll := &Collection{
		db:  odb,
		svc: &SecretService{},
	}

	item := newItem(nil, coll, entry)

	// Test basic properties.
	if item.Label() != "Test Entry" {
		t.Errorf("item label = %q, want %q", item.Label(), "Test Entry")
	}
	if item.Locked() {
		t.Error("item should not be locked")
	}
	if item.Created() != time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Errorf("created timestamp = %d, want %d", item.Created(), time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	}
	if item.Modified() != time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC).Unix() {
		t.Errorf("modified timestamp = %d, want %d", item.Modified(), time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC).Unix())
	}

	// Test attributes.
	attrs := item.Attributes()
	if attrs[AttrTitle] != "Test Entry" {
		t.Errorf("attribute title = %q, want %q", attrs[AttrTitle], "Test Entry")
	}
	if attrs[AttrUserName] != "testuser" {
		t.Errorf("attribute username = %q, want %q", attrs[AttrUserName], "testuser")
	}
	if attrs[AttrURL] != "https://example.com" {
		t.Errorf("attribute URL = %q, want %q", attrs[AttrURL], "https://example.com")
	}
	if attrs[AttrDBNamePrefix] != "Test.kdbx" {
		t.Errorf("attribute dbname = %q, want %q", attrs[AttrDBNamePrefix], "Test.kdbx")
	}
}
