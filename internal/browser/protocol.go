package browser

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Protocol version reported in responses.
const protocolVersion = "2.7.0"

// messageMaxSize is the maximum allowed message payload size (1 MiB).
const messageMaxSize = 1 << 20

// Request is the top-level JSON message from the browser.
type Request struct {
	Action    string          `json:"action"`
	Message   string          `json:"message,omitempty"`   // base64, encrypted
	Nonce     string          `json:"nonce,omitempty"`     // base64, 24 bytes
	PublicKey string          `json:"publicKey,omitempty"` // base64, for change-public-keys
	ClientID  string          `json:"clientID,omitempty"`  // base64, 24 bytes
	RequestID string          `json:"requestID,omitempty"` // for generate-password
}

// Response is the top-level JSON message sent to the browser.
type Response struct {
	Action   string `json:"action,omitempty"`
	Message  string `json:"message,omitempty"`  // base64, encrypted
	Nonce    string `json:"nonce,omitempty"`    // base64, 24 bytes
	Version  string `json:"version,omitempty"`
	Success  string `json:"success"`            // "true" or "false"
	PublicKey string `json:"publicKey,omitempty"`
	Error    string `json:"error,omitempty"`
	ErrorCode int    `json:"errorCode,omitempty"`
	Hash     string `json:"hash,omitempty"`
	ID       string `json:"id,omitempty"`
	Count    string `json:"count,omitempty"`
	Entries  any    `json:"entries,omitempty"`
	Password string `json:"password,omitempty"`
	Totp     string `json:"totp,omitempty"`
}

// readMessage reads a length-prefixed JSON message from the connection.
// Format: 4 bytes big-endian length, then JSON body.
func readMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("browser: read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 || length > messageMaxSize {
		return nil, fmt.Errorf("browser: invalid message length %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("browser: read body: %w", err)
	}
	return buf, nil
}

// writeMessage writes a length-prefixed JSON message to the connection.
func writeMessage(w io.Writer, data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("browser: write length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("browser: write body: %w", err)
	}
	return nil
}

// encodeResponse marshals a response to JSON and writes it length-prefixed.
func encodeResponse(w io.Writer, resp *Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("browser: marshal response: %w", err)
	}
	slog.Debug("browser: response", "action", resp.Action, "success", resp.Success)
	return writeMessage(w, data)
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("browser: random: %w", err)
	}
	return b, nil
}
