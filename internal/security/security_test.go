//go:build linux

package security

import (
	"bytes"
	"testing"
	"unsafe"
)

// TestAllocAndWipe verifies that Alloc returns locked memory and Wipe zeros it.
func TestAllocAndWipe(t *testing.T) {
	b, err := Alloc(32)
	if err != nil {
		t.Fatalf("Alloc failed: %v", err)
	}
	for i := range b {
		b[i] = byte(i + 1)
	}
	Wipe(b)
	if !bytes.Equal(b, make([]byte, 32)) {
		t.Error("Wipe did not zero the slice")
	}
}

// TestSecureStringLifecycle verifies creation, copy, and destruction.
func TestSecureStringLifecycle(t *testing.T) {
	ss, err := NewSecureString("hello")
	if err != nil {
		t.Fatalf("NewSecureString failed: %v", err)
	}
	if ss.Len() != 5 {
		t.Errorf("Len = %d, want 5", ss.Len())
	}
	copy := ss.Bytes()
	if string(copy) != "hello" {
		t.Errorf("Bytes = %q, want %q", copy, "hello")
	}
	ss.Destroy()
	if ss.Len() != 0 {
		t.Error("Destroy should leave length 0")
	}
}

// TestSecureStringNilBytes verifies Bytes on a nil SecureString returns nil.
func TestSecureStringNilBytes(t *testing.T) {
	var ss *SecureString
	if ss.Bytes() != nil {
		t.Error("nil SecureString.Bytes should return nil")
	}
	if ss.Len() != 0 {
		t.Error("nil SecureString.Len should return 0")
	}
}

// TestSecureSliceLifecycle verifies allocation, data access, and destruction.
func TestSecureSliceLifecycle(t *testing.T) {
	s, err := NewSecureSlice(16)
	if err != nil {
		t.Fatalf("NewSecureSlice failed: %v", err)
	}
	data := s.Data()
	if len(data) != 16 {
		t.Errorf("Data len = %d, want 16", len(data))
	}
	for i := range data {
		data[i] = 0xAA
	}
	s.Destroy()
	if s.Data() != nil {
		t.Error("Destroy should nil the slice")
	}
}

// TestMlockEmptySlice verifies Mlock/Munlock on empty slices are no-ops.
func TestMlockEmptySlice(t *testing.T) {
	if err := Mlock(nil); err != nil {
		t.Errorf("Mlock(nil) returned error: %v", err)
	}
	if err := Munlock(nil); err != nil {
		t.Errorf("Munlock(nil) returned error: %v", err)
	}
}

// TestMemsetAndMemclr verifies the low-level memory helpers.
func TestMemsetAndMemclr(t *testing.T) {
	b := make([]byte, 8)
	Memset(b, 0x42)
	want := bytes.Repeat([]byte{0x42}, 8)
	if !bytes.Equal(b, want) {
		t.Errorf("Memset result = %x, want %x", b, want)
	}
	Memclr(unsafe.Pointer(&b[0]), len(b))
	if !bytes.Equal(b, make([]byte, 8)) {
		t.Errorf("Memclr result = %x, want zeros", b)
	}
}

// TestSecureBool verifies the secure boolean wrapper.
func TestSecureBool(t *testing.T) {
	b := NewSecureBool(true)
	if !b.Value() {
		t.Error("SecureBool(true).Value() should be true")
	}
	b.Destroy()
	if b.Value() {
		t.Error("SecureBool.Destroy should zero the value")
	}

	var nilBool *SecureBool
	if nilBool.Value() {
		t.Error("nil SecureBool.Value() should be false")
	}
}
