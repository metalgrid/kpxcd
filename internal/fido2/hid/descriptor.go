//go:build linux

// Package hid implements a CTAP2 authenticator over a virtual FIDO HID
// device (Linux /dev/uhid). It speaks CTAPHID framing and the CTAP2 core
// command surface (GetInfo, MakeCredential, GetAssertion) against a
// CredentialStore, gating every credential operation behind a Gate.
//
// The package does not parse databases, sign with stored keys, or talk to
// polkit; it is the wire boundary only. Nil or failed gates deny.
package hid

import "fmt"

// Virtual device identity. These are not real vendor IDs; the shipped udev
// rule must match this exact VID:PID pair.
const (
	VendorID  = 0x2F7C
	ProductID = 0x2F7C
	BusUSB    = 0x03

	// DeviceName appears as the HID device name.
	DeviceName = "kpxcd virtual authenticator"
)

// reportDescriptor returns the HID report descriptor for a CTAPHID device:
// usage page 0xF1D0, one 64-byte input report and one 64-byte output
// report, no report ID. Chromium's discovery filter accepts exactly this
// shape (max report sizes in (7, 64]).
func reportDescriptor() []byte {
	return []byte{
		0x06, 0xD0, 0xF1, // Usage Page (0xF1D0, FIDO Alliance)
		0x09, 0x01, // Usage (0x01, CTAPHID)
		0xA1, 0x01, // Collection (Application)
		0x09, 0x20, //   Usage (0x20, Input Report Data)
		0x15, 0x00, //   Logical Minimum (0)
		0x26, 0xFF, 0x00, //   Logical Maximum (255)
		0x75, 0x08, //   Report Size (8)
		0x95, 0x40, //   Report Count (64)
		0x81, 0x02, //   Input (Data, Variable, Absolute)
		0x09, 0x21, //   Usage (0x21, Output Report Data)
		0x15, 0x00, //   Logical Minimum (0)
		0x26, 0xFF, 0x00, //   Logical Maximum (255)
		0x75, 0x08, //   Report Size (8)
		0x95, 0x40, //   Report Count (64)
		0x91, 0x02, //   Output (Data, Variable, Absolute)
		0xC0, // End Collection
	}
}

// CTAPHID protocol constants (FIDO client-to-authenticator spec).
const (
	reportSize     = 64 // HID report payload size, no report ID
	initHeaderLen  = 7  // cid(4) + cmd(1) + len(2)
	contHeaderLen  = 5  // cid(4) + seq(1)
	initPayloadLen = reportSize - initHeaderLen
	contPayloadLen = reportSize - contHeaderLen

	// maxMessageLen bounds inbound CTAPHID payloads; it matches the
	// maxMsgSize the authenticator advertises in GetInfo.
	maxMessageLen = 1024

	// broadcastChannel is the CID used for CTAPHID_INIT.
	broadcastChannel = 0xFFFFFFFF

	// typeInit marks command frames; continuation frames clear this bit.
	typeInit = 0x80
)

// CTAPHID commands (bit 7 set on the wire).
const (
	cmdPing      = 0x01
	cmdMsg       = 0x03 // CTAP1; unsupported
	cmdWink      = 0x08
	cmdInit      = 0x06
	cmdCBOR      = 0x10
	cmdCancel    = 0x11
	cmdError     = 0x3F
	cmdKeepalive = 0x3B
)

// CTAPHID capability flags for the INIT reply.
const (
	capWink = 0x01
	capCBOR = 0x04
)

// CTAPHID error codes.
const (
	errInvalidCmd = 0x01
	errInvalidSeq = 0x04
	errMsgTooLong = 0x05
	errChanBusy   = 0x06
	errOther      = 0x0A
)

// keepaliveStatus values.
const (
	statusIdle       = 0x01
	statusProcessing = 0x02
)

// hostMessage is one fully reassembled CTAPHID command from the client.
type hostMessage struct {
	channelID uint32
	command   byte // typeInit-cleared command byte for CBOR/MSG payloads
	payload   []byte
}

// decodeReport consumes one 64-byte host report and either returns a
// complete hostMessage or feeds the per-channel reassembly state. A nil
// message with a nil error means "more reports needed".
func (a *Authenticator) decodeReport(report []byte) (*hostMessage, error) {
	if len(report) != reportSize {
		return nil, fmt.Errorf("hid: report must be %d bytes, got %d", reportSize, len(report))
	}
	channelID := uint32(report[0])<<24 | uint32(report[1])<<16 | uint32(report[2])<<8 | uint32(report[3])

	if report[4]&typeInit == 0 {
		// Continuation frame.
		st, ok := a.reassembly[channelID]
		if !ok || st == nil {
			return nil, fmt.Errorf("hid: continuation frame on channel %#08x without an open message", channelID)
		}
		seq := report[4]
		if seq != st.nextSeq {
			return nil, fmt.Errorf("hid: unexpected sequence %d on channel %#08x, want %d", seq, channelID, st.nextSeq)
		}
		st.nextSeq++
		chunk := report[contHeaderLen:]
		if len(st.payload)+len(chunk) > maxMessageLen {
			return nil, fmt.Errorf("hid: message on channel %#08x exceeds %d bytes", channelID, maxMessageLen)
		}
		st.payload = append(st.payload, chunk...)
		if len(st.payload) >= st.totalLen {
			msg := &hostMessage{channelID: channelID, command: st.command, payload: st.payload[:st.totalLen]}
			delete(a.reassembly, channelID)
			return msg, nil
		}
		return nil, nil
	}

	command := report[4] &^ typeInit
	totalLen := int(report[5])<<8 | int(report[6])
	if totalLen > maxMessageLen {
		return nil, fmt.Errorf("hid: message of %d bytes exceeds %d", totalLen, maxMessageLen)
	}
	chunk := report[initHeaderLen:]
	if totalLen <= len(chunk) {
		return &hostMessage{channelID: channelID, command: command, payload: chunk[:totalLen]}, nil
	}
	a.reassembly[channelID] = &reassemblyState{
		command:  command,
		totalLen: totalLen,
		payload:  append([]byte{}, chunk...),
		nextSeq:  0,
	}
	return nil, nil
}

// reassemblyState tracks a partially received inbound message.
type reassemblyState struct {
	command  byte
	totalLen int
	payload  []byte
	nextSeq  byte
}

// encodeInitReply frames a complete device-to-host message into 64-byte
// HID reports: an init frame (0x80|command, big-endian length) followed by
// continuation frames.
func encodeInitReply(channelID uint32, command byte, payload []byte) [][]byte {
	var reports [][]byte

	first := make([]byte, reportSize)
	first[0], first[1], first[2], first[3] = byte(channelID>>24), byte(channelID>>16), byte(channelID>>8), byte(channelID)
	first[4] = command | typeInit
	first[5], first[6] = byte(len(payload)>>8), byte(len(payload))
	n := copy(first[initHeaderLen:], payload)
	reports = append(reports, first)

	for offset := n; offset < len(payload); {
		cont := make([]byte, reportSize)
		cont[0], cont[1], cont[2], cont[3] = byte(channelID>>24), byte(channelID>>16), byte(channelID>>8), byte(channelID)
		cont[4] = byte(offset-n) / contPayloadLen // sequence number
		written := copy(cont[contHeaderLen:], payload[offset:])
		offset += written
		reports = append(reports, cont)
	}
	return reports
}

// encodeInitResponse builds the 17-byte CTAPHID_INIT reply payload:
// nonce(8) + newCID(4) + protocolVersion(2) + version(3) + capabilities(1).
func encodeInitResponse(nonce []byte, newChannelID uint32) []byte {
	payload := make([]byte, 17)
	copy(payload[:8], nonce)
	payload[8], payload[9], payload[10], payload[11] = byte(newChannelID>>24), byte(newChannelID>>16), byte(newChannelID>>8), byte(newChannelID)
	payload[12] = 2 // CTAPHID protocol version
	payload[13] = 3 // device version major
	payload[14] = 0 // device version minor
	payload[15] = 0 // device version build
	payload[16] = capCBOR
	return payload
}

// encodeKeepalive builds a CTAPHID_KEEPALIVE payload.
func encodeKeepalive(status byte) []byte {
	return []byte{status}
}
