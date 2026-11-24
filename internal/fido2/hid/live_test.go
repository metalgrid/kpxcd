//go:build linux

package hid

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Live kernel round-trips: create the virtual device via /dev/uhid, then
// speak CTAPHID to it through the resulting hidraw node — the same path a
// browser takes. Every spec skips when /dev/uhid or the hidraw node is
// not accessible to the runner.

// liveAuthenticator creates the virtual device and returns it with an
// open hidraw node.
func liveAuthenticator(store CredentialStore) (*Authenticator, *os.File, context.CancelFunc) {
	if _, err := os.Stat("/dev/uhid"); err != nil {
		Skip("/dev/uhid does not exist")
	}
	f, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
	if err != nil {
		Skip("/dev/uhid not accessible to this user (ACL?): " + err.Error())
	}
	f.Close()

	a := NewAuthenticator(store, allowGate{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	Expect(a.Start(ctx)).To(Succeed())

	// The kernel attaches the hidraw node asynchronously after UHID_START.
	var nodes []string
	Eventually(func() []string {
		nodes, _ = a.dev.HidrawNodes(ctx)
		return nodes
	}, "5s").ShouldNot(BeEmpty())

	hidraw, err := os.OpenFile(filepath.Join("/dev", filepath.Base(nodes[0])), os.O_RDWR, 0)
	if err != nil {
		cancel()
		a.Close()
		Skip("hidraw node not accessible (udev uaccess grant missing): " + err.Error())
	}
	return a, hidraw, cancel
}

// writeCTAP writes one complete CTAPHID command the way Chromium does:
// every report prefixed with a 0x00 report-ID byte.
func writeCTAP(hidraw *os.File, cid uint32, command byte, payload []byte) {
	for _, frame := range buildRequest(cid, command, payload) {
		prefixed := append([]byte{0x00}, frame...)
		Expect(prefixed).To(HaveLen(reportSize + 1))
		n, err := hidraw.Write(prefixed)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(reportSize + 1))
	}
}

// readCTAP reads one complete device message from the hidraw node and
// returns the command byte (typeInit cleared) plus the payload.
func readCTAP(hidraw *os.File) (byte, []byte) {
	first := make([]byte, reportSize)
	n, err := hidraw.Read(first)
	Expect(err).NotTo(HaveOccurred())
	Expect(n).To(Equal(reportSize))
	command := first[4] &^ typeInit
	total := int(first[5])<<8 | int(first[6])
	body := append([]byte{}, first[initHeaderLen:]...)
	for len(body) < total {
		next := make([]byte, reportSize)
		_, err := hidraw.Read(next)
		Expect(err).NotTo(HaveOccurred())
		body = append(body, next[contHeaderLen:]...)
	}
	return command, body[:total]
}

// allocateLiveChannel runs the CTAPHID_INIT handshake on a live device.
func allocateLiveChannel(hidraw *os.File) uint32 {
	nonce := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	writeCTAP(hidraw, broadcastChannel, cmdInit, nonce)
	command, payload := readCTAP(hidraw)
	Expect(command).To(Equal(byte(cmdInit)))
	Expect(payload[:8]).To(Equal(nonce))
	Expect(payload[16]).To(Equal(byte(capCBOR | capNMSG)))
	newCID := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])
	Expect(newCID).NotTo(Equal(uint32(broadcastChannel)))
	return newCID
}

// canonicalEC2Key mirrors the CTAP-canonical COSE EC2 field order the
// service encodes. The test cannot import fido2 for its encoder (that
// would cycle), so the wire assertions below pin the byte layout here.
type canonicalEC2Key struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

var _ = Describe("live uhid transport", func() {
	It("answers a CTAPHID_INIT written to the hidraw node", func() {
		a, hidraw, cancel := liveAuthenticator(&stubStore{creds: true})
		defer func() { cancel(); a.Close() }()

		allocateLiveChannel(hidraw)
	})

	It("answers a Chrome-style GetInfo round-trip", func() {
		a, hidraw, cancel := liveAuthenticator(&stubStore{creds: true})
		defer func() { cancel(); a.Close() }()
		cid := allocateLiveChannel(hidraw)

		writeCTAP(hidraw, cid, cmdCBOR, []byte{cmdGetInfo})
		command, payload := readCTAP(hidraw)
		Expect(command).To(Equal(byte(cmdCBOR)))
		Expect(payload[0]).To(Equal(byte(0x00))) // CTAP2_OK
		GinkgoWriter.Printf("GetInfo reply: total=%d body=% x\n", len(payload)-1, payload[1:])
	})

	It("registers a passkey through the kernel with a canonical COSE key", func() {
		// A real P-256 key so the COSE bytes on the wire are exactly
		// what Chrome would parse after a passkey create.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		key := canonicalEC2Key{
			Kty: 2, // EC2
			Alg: -7,
			Crv: 1, // P-256
			X:   priv.X.FillBytes(make([]byte, 32)),
			Y:   priv.Y.FillBytes(make([]byte, 32)),
		}
		cose, err := cbor.Marshal(key)
		Expect(err).NotTo(HaveOccurred())

		a, hidraw, cancel := liveAuthenticator(&stubStore{creds: true, cose: cose})
		defer func() { cancel(); a.Close() }()
		cid := allocateLiveChannel(hidraw)

		clientDataHash := bytes.Repeat([]byte{0x5A}, 32)
		req, err := marshalRequest(map[interface{}]interface{}{
			1: clientDataHash,
			2: map[string]interface{}{"id": "example.com", "name": "Example"},
			3: map[string]interface{}{"id": []byte{9, 9}, "name": "user", "displayName": "User"},
			4: []interface{}{map[string]interface{}{"type": "public-key", "alg": -7}},
		})
		Expect(err).NotTo(HaveOccurred())
		writeCTAP(hidraw, cid, cmdCBOR, append([]byte{cmdMakeCredential}, req...))

		command, payload := readCTAP(hidraw)
		Expect(command).To(Equal(byte(cmdCBOR)))
		Expect(payload[0]).To(Equal(byte(statusOK)), "MakeCredential must succeed through the kernel")

		var resp map[interface{}]interface{}
		Expect(cbor.Unmarshal(payload[1:], &resp)).To(Succeed())
		resp = normalizeMap(resp)
		Expect(resp[1]).To(Equal("none"))

		// authenticatorData: rpIDHash(32) flags(1) signCount(4)
		// aaguid(16) credIDLen(2) credID COSE key.
		authData, ok := resp[2].([]byte)
		Expect(ok).To(BeTrue())
		Expect(authData[32]&FlagUP).NotTo(Equal(byte(0)), "user presence flag set")
		Expect(authData[32]&FlagAT).NotTo(Equal(byte(0)), "attested credential data present")
		Expect(authData[37:53]).To(Equal([]byte{0xab, 0x44, 0x9b, 0x5e, 0xd0, 0xbf, 0x4d, 0x8d, 0x81, 0xb1, 0xde, 0x5e, 0xc1, 0xa8, 0xc0, 0x0e}))
		credLen := int(authData[53])<<8 | int(authData[54])
		Expect(credLen).To(BeNumerically(">", 0))
		coseWire := authData[55+credLen:]
		Expect(len(coseWire)).To(Equal(77), "COSE key: map(5) + 5 fixed fields + 2x32-byte coordinates")

		// The exact canonical byte layout: keys 1, 3, -1, -2, -3 in
		// order; alg (0x26 = -7) before the negative keys; both
		// coordinates 0x58 0x20-prefixed 32-byte strings.
		Expect(hex.EncodeToString(coseWire[:10])).To(Equal("a5010203262001215820"))
		Expect(hex.EncodeToString(coseWire[42:45])).To(Equal("225820"))
	})
})
