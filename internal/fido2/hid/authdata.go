//go:build linux

package hid

import (
	"crypto/sha256"
	"fmt"
)

// CTAP2 command identifiers.
const (
	cmdMakeCredential = 0x01
	cmdGetAssertion   = 0x02
	cmdGetInfo        = 0x04
)

// CTAP2 status codes (single-byte CBOR-less replies on failure).
const (
	statusOK                   byte = 0x00
	statusUnsupportedCommand   byte = 0x02
	statusInvalidCBOR          byte = 0x03
	statusMissingParam         byte = 0x05
	statusInvalidCredential    byte = 0x16
	statusUnsupportedAlgorithm byte = 0x1A
	statusOperationDenied      byte = 0x1B
	statusNoCredentials        byte = 0x22
	statusUserActionTimeout    byte = 0x23
)

// WebAuthn authenticator flag bits (wire values).
const (
	FlagUP = 0x01 // User Present
	FlagUV = 0x04 // User Verified
	FlagBE = 0x08 // Backup Eligible
	FlagBS = 0x10 // Backup State
	FlagAT = 0x40 // Attested Credential Data
	FlagED = 0x80 // Extension Data
)

// authenticatorData assembles authenticator data: rpIDHash (32) + flags
// (1) + signCount (4) + optional attested credential data.
func authenticatorData(rpID string, flags byte, signCount uint32, attested []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	data := make([]byte, 0, 37+len(attested))
	data = append(data, rpIDHash[:]...)
	data = append(data, flags)
	data = append(data, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	data = append(data, attested...)
	return data
}

// attestedCredentialData builds AAGUID(16) + credIDLen(2) + credentialID +
// COSE public key. The AAGUID matches the KeePassXC convention the service
// stores.
func attestedCredentialData(credentialID, coseKey []byte) ([]byte, error) {
	if len(credentialID) == 0 || len(credentialID) > 1023 {
		return nil, fmt.Errorf("hid: credential ID length %d out of range", len(credentialID))
	}
	if len(coseKey) == 0 {
		return nil, fmt.Errorf("hid: missing COSE public key")
	}
	out := make([]byte, 0, aaguidLen+2+len(credentialID)+len(coseKey))
	out = append(out, aaguid[:]...)
	out = append(out, byte(len(credentialID)>>8), byte(len(credentialID)))
	out = append(out, credentialID...)
	out = append(out, coseKey...)
	return out, nil
}

const aaguidLen = 16

// aaguid is the kpxcd software authenticator AAGUID (KeePassXC convention).
var aaguid = [aaguidLen]byte{
	0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15,
	0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc, 0x7d,
}
