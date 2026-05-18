//go:build linux

// Package sshagent implements an OpenSSH-compatible SSH agent server.
package sshagent

import (
	"encoding/binary"
	"fmt"
	"io"
)

// SSH agent protocol message types (from draft-miller-ssh-agent-00).
const (
	SSHAgentFailure            = 5
	SSHAgentSuccess            = 6
	SSHAgentCRequestIdentities = 11
	SSHAgentIdentitiesAnswer   = 12
	SSHAgentCAddIdentity       = 17
	SSHAgentCRemoveIdentity    = 18
	SSHAgentCRemoveAllIdentities = 19
	SSHAgentCAddIdConstrained  = 25
	SSHAgentCSignRequest       = 13
	SSHAgentSignResponse       = 14
	// SSH1 legacy — not implemented but handled gracefully.
	SSHAgentCRemoveAllRsaIdentities = 9
)

// Constraint types for constrained key addition.
const (
	SSHAgentConstrainLifetime = 1
	SSHAgentConstrainConfirm   = 2
	SSHAgentConstrainExtension = 255
)

// maxMessageLen is the maximum SSH agent message length (8 MiB).
const maxMessageLen = 8 * 1024 * 1024

// readMessage reads a length-prefixed SSH agent message from r.
// The wire format is: 4-byte big-endian length, then that many bytes of payload.
func readMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > maxMessageLen {
		return nil, fmt.Errorf("sshagent: message too large: %d bytes", length)
	}
	if length == 0 {
		return nil, fmt.Errorf("sshagent: zero-length message")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeMessage writes a length-prefixed SSH agent message to w.
func writeMessage(w io.Writer, msg []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(msg)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// writeSuccess writes a SSH_AGENT_SUCCESS response.
func writeSuccess(w io.Writer) error {
	return writeMessage(w, []byte{SSHAgentSuccess})
}

// writeFailure writes a SSH_AGENT_FAILURE response.
func writeFailure(w io.Writer) error {
	return writeMessage(w, []byte{SSHAgentFailure})
}

// encodeIdentitiesAnswer encodes a list of key blobs + comments as an
// SSH_AGENT_IDENTITIES_ANSWER message.
func encodeIdentitiesAnswer(blobs [][]byte, comments []string) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, SSHAgentIdentitiesAnswer)
	buf = encodeUint32(buf, uint32(len(blobs)))
	for i := range blobs {
		buf = encodeString(buf, blobs[i])
		comment := ""
		if i < len(comments) {
			comment = comments[i]
		}
		buf = encodeString(buf, []byte(comment))
	}
	return buf
}

// encodeString appends a length-prefixed string to buf.
func encodeString(buf []byte, data []byte) []byte {
	buf = encodeUint32(buf, uint32(len(data)))
	return append(buf, data...)
}

// encodeUint32 appends a big-endian uint32 to buf.
func encodeUint32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// decodeMessageType returns the first byte (message type) and the remaining
// payload.
func decodeMessageType(msg []byte) (byte, []byte) {
	if len(msg) == 0 {
		return 0, nil
	}
	return msg[0], msg[1:]
}

// decodeString reads a length-prefixed string from data.
// Returns the string bytes and the remaining data, or nil if parsing fails.
func decodeString(data []byte) ([]byte, []byte) {
	if len(data) < 4 {
		return nil, nil
	}
	length := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if uint32(len(data)) < length {
		return nil, nil
	}
	return data[:length], data[length:]
}

// decodeUint32 reads a big-endian uint32 from data.
func decodeUint32(data []byte) (uint32, []byte) {
	if len(data) < 4 {
		return 0, nil
	}
	return binary.BigEndian.Uint32(data[:4]), data[4:]
}

// decodeUint8 reads a single byte from data.
func decodeUint8(data []byte) (byte, []byte) {
	if len(data) == 0 {
		return 0, nil
	}
	return data[0], data[1:]
}
