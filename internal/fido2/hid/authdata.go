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

// CTAP2 status codes (single-byte replies on failure). Values per the
// CTAP 2.0 §6.3 / CTAP 2.1 §8.2 status tables; hosts map every code to a
// distinct outcome, so a wrong value misleads the client UI.
const (
	statusOK                   byte = 0x00
	statusInvalidCommand       byte = 0x01 // CTAP1_ERR_INVALID_COMMAND: sent for unknown CTAP2 commands (CTAP 2.1 §8.1)
	statusInvalidParameter     byte = 0x02
	statusInvalidLength        byte = 0x03
	statusUnexpectedType       byte = 0x11
	statusInvalidOption        byte = 0x2c
	statusPINAuthInvalid       byte = 0x33
	statusPINNotSet            byte = 0x35
	statusRequestTooLarge      byte = 0x39
	statusInvalidCBOR          byte = 0x12 // CTAP2_ERR_INVALID_CBOR
	statusMissingParam         byte = 0x14 // CTAP2_ERR_MISSING_PARAMETER
	statusCredentialExcluded   byte = 0x19 // CTAP2_ERR_CREDENTIAL_EXCLUDED
	statusInvalidCredential    byte = 0x22 // CTAP2_ERR_INVALID_CREDENTIAL
	statusUnsupportedAlgorithm byte = 0x26 // CTAP2_ERR_UNSUPPORTED_ALGORITHM
	statusOperationDenied      byte = 0x27 // CTAP2_ERR_OPERATION_DENIED
	statusKeepaliveCancel      byte = 0x2D // CTAP2_ERR_KEEPALIVE_CANCEL
	statusNoCredentials        byte = 0x2E // CTAP2_ERR_NO_CREDENTIALS
	statusUserActionTimeout    byte = 0x2F // CTAP2_ERR_USER_ACTION_TIMEOUT
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
// COSE public key, using the fixed kpxcd product identity.
func attestedCredentialData(credentialID, coseKey []byte) ([]byte, error) {
	if len(credentialID) == 0 || len(credentialID) > 1023 {
		return nil, fmt.Errorf("hid: credential ID length %d out of range", len(credentialID))
	}
	if len(coseKey) == 0 {
		return nil, fmt.Errorf("hid: missing COSE public key")
	}
	out := make([]byte, 0, aaguidLen+2+len(credentialID)+len(coseKey))
	out = append(out, productAAGUID...)
	out = append(out, byte(len(credentialID)>>8), byte(len(credentialID)))
	out = append(out, credentialID...)
	out = append(out, coseKey...)
	return out, nil
}

const aaguidLen = 16

// productAAGUID is the immutable wire encoding of the kpxcd model identity,
// ab449b5e-d0bf-4d8d-81b1-de5ec1a8c00e. It is not installation configuration.
const productAAGUID = "\xab\x44\x9b\x5e\xd0\xbf\x4d\x8d\x81\xb1\xde\x5e\xc1\xa8\xc0\x0e"
