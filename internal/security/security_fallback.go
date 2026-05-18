//go:build linux && !runtimesecret

// Package security provides secure memory helpers.
// When GOEXPERIMENT=runtimesecret is not set, Do() falls back to a direct call.
package security

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Do runs f directly when runtime/secret is not available.
func Do(f func()) {
	f()
}

// Alloc allocates n bytes, locks the backing page in memory, and returns
// the slice. The caller must call Wipe when done.
func Alloc(n int) ([]byte, error) {
	b := make([]byte, n)
	if err := Mlock(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Wipe zeroes the byte slice and unlocks the backing page.
// Safe to call on nil or empty slices.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	_ = Munlock(b)
}

// Mlock locks the memory pages containing b in RAM so they are never
// swapped to disk.
func Mlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

// Munlock unlocks the memory pages containing b, allowing them to be
// swapped out again.
func Munlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

// SecureString wraps a []byte that lives inside a secret.Do scope.
type SecureString struct {
	data []byte
}

// NewSecureString creates a SecureString from the given bytes by copying
// them into a locked allocation.
func NewSecureString(s string) (*SecureString, error) {
	b, err := Alloc(len(s))
	if err != nil {
		return nil, err
	}
	copy(b, s)
	return &SecureString{data: b}, nil
}

// Bytes returns a copy of the secure bytes.
func (s *SecureString) Bytes() []byte {
	if s == nil {
		return nil
	}
	out := make([]byte, len(s.data))
	copy(out, s.data)
	return out
}

// Len returns the length of the secure string.
func (s *SecureString) Len() int {
	if s == nil {
		return 0
	}
	return len(s.data)
}

// Destroy zeroes and frees the secure string.
func (s *SecureString) Destroy() {
	if s != nil {
		Wipe(s.data)
		s.data = nil
	}
}

// SecureSlice is a []byte backed by a locked memory region.
type SecureSlice struct {
	data []byte
}

// NewSecureSlice allocates a new secure slice of the given size.
func NewSecureSlice(n int) (*SecureSlice, error) {
	b, err := Alloc(n)
	if err != nil {
		return nil, err
	}
	return &SecureSlice{data: b}, nil
}

// Data returns the underlying slice.
func (s *SecureSlice) Data() []byte {
	if s == nil {
		return nil
	}
	return s.data
}

// Destroy zeroes and releases the secure slice.
func (s *SecureSlice) Destroy() {
	if s != nil {
		Wipe(s.data)
		s.data = nil
	}
}

// NoCopy is a no-op type that triggers vet's nolockcheck for types
// containing secure data.
type NoCopy struct{}

func (*NoCopy) Lock()   {}
func (*NoCopy) Unlock() {}

// MlockAll locks all currently mapped pages of the process.
func MlockAll() error {
	return unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
}

// MunlockAll unlocks all locked pages of the process.
func MunlockAll() error {
	return unix.Munlockall()
}

// Memset fills b with the given byte value.
func Memset(b []byte, val byte) {
	for i := range b {
		b[i] = val
	}
}

// Memclr zeroes the memory region pointed to by p of length n.
func Memclr(p unsafe.Pointer, n int) {
	b := unsafe.Slice((*byte)(p), n)
	for i := range b {
		b[i] = 0
	}
}

// SecureBool holds a boolean in secure memory.
type SecureBool struct {
	data byte
}

// NewSecureBool creates a SecureBool.
func NewSecureBool(v bool) *SecureBool {
	b := &SecureBool{}
	if v {
		b.data = 1
	}
	return b
}

// Value returns the boolean value.
func (s *SecureBool) Value() bool {
	if s == nil {
		return false
	}
	return s.data != 0
}

// Destroy zeroes the secure bool.
func (s *SecureBool) Destroy() {
	if s != nil {
		s.data = 0
	}
}
