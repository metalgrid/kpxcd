//go:build linux

package sshagent

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/metalgrid/kpxcd/internal/config"
	"golang.org/x/crypto/ssh"
)

// TestReadMessageWriteMessageRoundtrip verifies that a message written
// with writeMessage can be read back with readMessage.
func TestReadMessageWriteMessageRoundtrip(t *testing.T) {
	tests := [][]byte{
		{SSHAgentCRequestIdentities},
		{SSHAgentIdentitiesAnswer, 0x00, 0x00, 0x00, 0x01},
		[]byte("hello world"),
		make([]byte, 1024),
	}

	for i, msg := range tests {
		t.Run("", func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeMessage(&buf, msg); err != nil {
				t.Fatalf("writeMessage failed: %v", err)
			}

			got, err := readMessage(&buf)
			if err != nil {
				t.Fatalf("readMessage failed: %v", err)
			}
			if !bytes.Equal(got, msg) {
				t.Errorf("roundtrip %d: got %d bytes, want %d bytes", i, len(got), len(msg))
			}
		})
	}
}

// TestWriteMessageLengthPrefix verifies that writeMessage writes the
// correct 4-byte big-endian length prefix.
func TestWriteMessageLengthPrefix(t *testing.T) {
	msg := []byte{0x01, 0x02, 0x03}
	var buf bytes.Buffer

	if err := writeMessage(&buf, msg); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}

	data := buf.Bytes()
	if len(data) != 7 { // 4 header + 3 payload
		t.Fatalf("expected 7 bytes total, got %d", len(data))
	}

	length := binary.BigEndian.Uint32(data[:4])
	if length != 3 {
		t.Errorf("length prefix = %d, want 3", length)
	}
	if !bytes.Equal(data[4:], msg) {
		t.Errorf("payload mismatch")
	}
}

// TestReadMessageTooLarge verifies that readMessage rejects messages
// exceeding maxMessageLen.
func TestReadMessageTooLarge(t *testing.T) {
	var buf bytes.Buffer
	// Write a header claiming 9 MiB.
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 9*1024*1024)
	buf.Write(hdr)
	buf.Write(make([]byte, 100)) // enough bytes for the header to be read

	_, err := readMessage(&buf)
	if err == nil {
		t.Fatal("expected error for too-large message, got nil")
	}
}

// TestReadMessageZeroLength verifies that readMessage rejects zero-length messages.
func TestReadMessageZeroLength(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 0)
	buf.Write(hdr)

	_, err := readMessage(&buf)
	if err == nil {
		t.Fatal("expected error for zero-length message, got nil")
	}
}

// TestEncodeIdentitiesAnswer verifies that encodeIdentitiesAnswer produces
// correctly formatted SSH agent identities answer messages.
func TestEncodeIdentitiesAnswer(t *testing.T) {
	blobs := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06, 0x07},
	}
	comments := []string{"key1", "key2"}

	result := encodeIdentitiesAnswer(blobs, comments)

	// First byte should be SSHAgentIdentitiesAnswer.
	if result[0] != SSHAgentIdentitiesAnswer {
		t.Errorf("first byte = %d, want %d", result[0], SSHAgentIdentitiesAnswer)
	}

	// Next 4 bytes: number of keys (2).
	numKeys := binary.BigEndian.Uint32(result[1:5])
	if numKeys != 2 {
		t.Errorf("numKeys = %d, want 2", numKeys)
	}

	// Decode the first blob.
	str1, rest1 := decodeString(result[5:])
	if str1 == nil {
		t.Fatal("failed to decode first blob string")
	}
	if !bytes.Equal(str1, blobs[0]) {
		t.Errorf("first blob mismatch")
	}

	// Decode the first comment.
	comment1, rest2 := decodeString(rest1)
	if comment1 == nil {
		t.Fatal("failed to decode first comment")
	}
	if string(comment1) != "key1" {
		t.Errorf("first comment = %q, want %q", comment1, "key1")
	}

	// Decode the second blob.
	str2, rest3 := decodeString(rest2)
	if str2 == nil {
		t.Fatal("failed to decode second blob string")
	}
	if !bytes.Equal(str2, blobs[1]) {
		t.Errorf("second blob mismatch")
	}

	// Decode the second comment.
	comment2, _ := decodeString(rest3)
	if comment2 == nil {
		t.Fatal("failed to decode second comment")
	}
	if string(comment2) != "key2" {
		t.Errorf("second comment = %q, want %q", comment2, "key2")
	}
}

// TestEncodeIdentitiesAnswerWithMoreBlobsThanComments verifies that
// encodeIdentitiesAnswer handles the case where there are more blobs
// than comments (defaulting to empty string).
func TestEncodeIdentitiesAnswerWithMoreBlobsThanComments(t *testing.T) {
	blobs := [][]byte{{0x01, 0x02}, {0x03, 0x04}}
	comments := []string{"only_one"}

	result := encodeIdentitiesAnswer(blobs, comments)

	// Skip message type (1 byte) and count (4 bytes).
	pos := 5

	// First key + comment.
	_, rest := decodeString(result[pos:]) // blob
	pos = len(result) - len(rest)
	c1, rest := decodeString(result[pos:])
	pos = len(result) - len(rest)
	if string(c1) != "only_one" {
		t.Errorf("first comment = %q, want %q", c1, "only_one")
	}

	// Second key + empty comment.
	_, rest = decodeString(result[pos:]) // blob
	pos = len(result) - len(rest)
	c2, _ := decodeString(result[pos:])
	if c2 == nil || len(c2) != 0 {
		t.Errorf("second comment should be empty, got %q", c2)
	}
}

// TestDecodeMessageType verifies that decodeMessageType correctly
// extracts the first byte and remaining payload.
func TestDecodeMessageType(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantType    byte
		wantPayload []byte
	}{
		{
			name:        "normal message",
			input:       []byte{0x11, 0x02, 0x03},
			wantType:    0x11,
			wantPayload: []byte{0x02, 0x03},
		},
		{
			name:        "single byte",
			input:       []byte{0x05},
			wantType:    0x05,
			wantPayload: nil,
		},
		{
			name:        "empty input",
			input:       []byte{},
			wantType:    0,
			wantPayload: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotPayload := decodeMessageType(tc.input)
			if gotType != tc.wantType {
				t.Errorf("type = 0x%02x, want 0x%02x", gotType, tc.wantType)
			}
			if !bytes.Equal(gotPayload, tc.wantPayload) {
				t.Errorf("payload = %v, want %v", gotPayload, tc.wantPayload)
			}
		})
	}
}

// TestDecodeString verifies that decodeString correctly parses length-prefixed
// strings.
func TestDecodeString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantStr  []byte
		wantRest []byte
		wantOK   bool
	}{
		{
			name:     "hello",
			input:    append([]byte{0x00, 0x00, 0x00, 0x05}, []byte("hello")...),
			wantStr:  []byte("hello"),
			wantRest: nil,
			wantOK:   true,
		},
		{
			name:     "empty string",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			wantStr:  []byte{},
			wantRest: nil,
			wantOK:   true,
		},
		{
			name:     "string with remaining data",
			input:    append(append([]byte{0x00, 0x00, 0x00, 0x03}, []byte("abc")...), 0xFF, 0xFE),
			wantStr:  []byte("abc"),
			wantRest: []byte{0xFF, 0xFE},
			wantOK:   true,
		},
		{
			name:   "too short for length",
			input:  []byte{0x00, 0x00, 0x01},
			wantOK: false,
		},
		{
			name:   "length exceeds data",
			input:  append([]byte{0x00, 0x00, 0x00, 0x10}, []byte("short")...),
			wantOK: false,
		},
		{
			name:   "nil input",
			input:  nil,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotStr, gotRest := decodeString(tc.input)
			if !tc.wantOK {
				if gotStr != nil {
					t.Errorf("expected nil string for invalid input, got %v", gotStr)
				}
				return
			}
			if gotStr == nil {
				t.Fatal("decodeString returned nil")
			}
			if !bytes.Equal(gotStr, tc.wantStr) {
				t.Errorf("string = %v, want %v", gotStr, tc.wantStr)
			}
			if !bytes.Equal(gotRest, tc.wantRest) {
				t.Errorf("rest = %v, want %v", gotRest, tc.wantRest)
			}
		})
	}
}

// TestEncodeString verifies that encodeString correctly appends a
// length-prefixed string.
func TestEncodeString(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantLen  uint32
		wantData []byte
	}{
		{
			name:     "hello",
			data:     []byte("hello"),
			wantLen:  5,
			wantData: []byte("hello"),
		},
		{
			name:     "empty",
			data:     []byte{},
			wantLen:  0,
			wantData: []byte{},
		},
		{
			name:     "binary data",
			data:     []byte{0x00, 0xFF, 0x80},
			wantLen:  3,
			wantData: []byte{0x00, 0xFF, 0x80},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf []byte
			buf = encodeString(buf, tc.data)

			if len(buf) < 4 {
				t.Fatal("encoded string too short for length prefix")
			}

			gotLen := binary.BigEndian.Uint32(buf[:4])
			if gotLen != tc.wantLen {
				t.Errorf("length prefix = %d, want %d", gotLen, tc.wantLen)
			}

			gotData := buf[4:]
			if !bytes.Equal(gotData, tc.wantData) {
				t.Errorf("data = %v, want %v", gotData, tc.wantData)
			}
		})
	}
}

// TestEncodeUint32 verifies that encodeUint32 correctly appends a
// big-endian uint32.
func TestEncodeUint32(t *testing.T) {
	tests := []struct {
		value uint32
		want  []byte
	}{
		{0x00000000, []byte{0x00, 0x00, 0x00, 0x00}},
		{0x00000001, []byte{0x00, 0x00, 0x00, 0x01}},
		{0x000000FF, []byte{0x00, 0x00, 0x00, 0xFF}},
		{0x0000FFFF, []byte{0x00, 0x00, 0xFF, 0xFF}},
		{0x00FFFFFF, []byte{0x00, 0xFF, 0xFF, 0xFF}},
		{0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{0x12345678, []byte{0x12, 0x34, 0x56, 0x78}},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			got := encodeUint32(nil, tc.value)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("encodeUint32(%d) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestProcessExtensionDoesNotCloseProtocol(t *testing.T) {
	s := &AgentServer{}
	resp, err := s.processMessage([]byte{SSHAgentCExtension})
	if err != nil {
		t.Fatalf("extension request returned error: %v", err)
	}
	if !bytes.Equal(resp, []byte{SSHAgentFailure}) {
		t.Fatalf("extension response = %v, want SSH_AGENT_FAILURE", resp)
	}
}

// FuzzReadMessage verifies that readMessage never panics on arbitrary input.
func FuzzReadMessage(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add(append([]byte{0x00, 0x00, 0x00, 0x05}, []byte("hello")...))
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := bytes.NewReader(data)
		_, _ = readMessage(buf)
	})
}

// FuzzDecodeString verifies that decodeString never panics on arbitrary input.
func FuzzDecodeString(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add(append([]byte{0x00, 0x00, 0x00, 0x05}, []byte("hello")...))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeString(data)
	})
}

// FuzzProcessMessage verifies that processMessage never panics on arbitrary
// SSH agent payloads.
func FuzzProcessMessage(f *testing.F) {
	f.Add([]byte{SSHAgentCRequestIdentities})
	f.Add([]byte{SSHAgentCRemoveAllIdentities})
	f.Add([]byte{SSHAgentCExtension, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		s := &AgentServer{manager: NewIdentityManager(&config.SSHAgentConfig{})}
		_, _ = s.processMessage(data)
	})
}

func TestSignatureAlgorithmForFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   uint32
		want    string
		wantErr bool
	}{
		{name: "default", flags: 0, want: ""},
		{name: "rsa sha256", flags: SSHAgentSignFlagRSASHA256, want: ssh.KeyAlgoRSASHA256},
		{name: "rsa sha512", flags: SSHAgentSignFlagRSASHA512, want: ssh.KeyAlgoRSASHA512},
		{name: "reserved", flags: SSHAgentSignFlagReserved, wantErr: true},
		{name: "conflicting", flags: SSHAgentSignFlagRSASHA256 | SSHAgentSignFlagRSASHA512, wantErr: true},
		{name: "unknown", flags: 0x80, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := signatureAlgorithmForFlags(tc.flags)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("algorithm = %q, want %q", got, tc.want)
			}
		})
	}
}
