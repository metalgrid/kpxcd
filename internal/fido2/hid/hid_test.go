//go:build linux

package hid

import (
	"context"
	"encoding/hex"
	"sync"

	"github.com/fxamacker/cbor/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeWriter captures reports the authenticator sends.
type fakeWriter struct {
	mu      sync.Mutex
	reports [][]byte
}

func (w *fakeWriter) writeReport(report []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reports = append(w.reports, append([]byte{}, report...))
	return nil
}

func (w *fakeWriter) all() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.reports))
	copy(out, w.reports)
	return out
}

// fakeEvents is a controllable kernel-event source.
type fakeEvents struct {
	ch chan event
}

func (f *fakeEvents) feedHostReport(report []byte) {
	f.ch <- event{isHostReport: true, report: report}
}

// stubStore is a CredentialStore with canned responses.
type stubStore struct {
	createCalls int
	denyAssert  bool
	creds       bool
}

func (s *stubStore) Create(rpID, rpName, userName, userDisplayName string) ([]byte, []byte, []byte, error) {
	s.createCalls++
	return []byte{0xAA, 0xBB}, []byte{0x01, 0x02}, []byte{0x01, 0x02, 0x03, 0x04, 0x05,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03}, nil
}

func (s *stubStore) Assert(rpID string, credentialID, clientDataHash []byte, userVerified bool) ([]byte, []byte, []byte, []byte, error) {
	if s.denyAssert {
		return nil, nil, nil, nil, ErrNoCredentials
	}
	authData := authenticatorData(rpID, FlagUP, 1, nil)
	sig := make([]byte, 70)
	return []byte{0xAA, 0xBB}, []byte{0x01, 0x02}, authData, sig, nil
}

func (s *stubStore) HasCredentialsForRPID(rpID string) (bool, error) {
	return s.creds, nil
}

// allowGate approves everything; denyGate refuses everything.
type allowGate struct{}

func (allowGate) Approve(context.Context, Operation) bool { return true }

type denyGate struct{}

func (denyGate) Approve(context.Context, Operation) bool { return false }

// newTestAuthenticator wires an authenticator to fakes and starts its loop.
func newTestAuthenticator(store CredentialStore, gate Gate) (*Authenticator, *fakeWriter, *fakeEvents, context.CancelFunc) {
	writer := &fakeWriter{}
	feeds := &fakeEvents{ch: make(chan event, 16)}
	a := NewAuthenticator(store, gate, nil)
	a.writer = writer
	a.events = feeds.ch
	ctx, cancel := context.WithCancel(context.Background())
	go a.run(ctx)
	return a, writer, feeds, cancel
}

// buildRequest frames a complete CTAPHID command into host reports.
func buildRequest(channelID uint32, command byte, payload []byte) [][]byte {
	return encodeInitReply(channelID, command, payload)
}

// firstCBORReply waits for the first CBOR reply report and returns its
// payload (status byte + optional CBOR body).
func firstCBORReply(writer *fakeWriter) (byte, []byte) {
	var reports [][]byte
	Eventually(func() int {
		reports = writer.all()
		for _, r := range reports {
			if r[4] == byte(cmdCBOR|typeInit) {
				return 1
			}
		}
		return 0
	}, "3s").Should(BeNumerically(">", 0))

	for _, r := range reports {
		if r[4] == byte(cmdCBOR|typeInit) {
			total := int(r[5])<<8 | int(r[6])
			payload := append([]byte{}, r[7:]...)
			for _, cont := range reports[1:] {
				if cont[4] < 0x80 && len(payload) < total {
					payload = append(payload, cont[5:]...)
				}
			}
			return payload[0], payload[1 : 1+total-1]
		}
	}
	return 0xFF, nil
}

var _ = Describe("CTAPHID framing", func() {
	It("segments outbound messages into init and continuation frames", func() {
		payload := make([]byte, 200)
		for i := range payload {
			payload[i] = byte(i)
		}
		reports := encodeInitReply(0x01020304, cmdCBOR, payload)
		Expect(reports).To(HaveLen(4)) // 57 + 59 + 59 + 25

		Expect(reports[0][4] & typeInit).NotTo(Equal(byte(0)))
		Expect(int(reports[0][5])<<8 | int(reports[0][6])).To(Equal(200))
		for i, report := range reports[1:] {
			Expect(report[4]).To(Equal(byte(i)), "continuation sequence numbers")
		}
	})

	It("reassembles multi-frame inbound commands", func() {
		a := NewAuthenticator(nil, nil, nil)
		payload := make([]byte, 100)
		for i := range payload {
			payload[i] = byte(0x42)
		}
		for _, report := range buildRequest(0x01020304, cmdCBOR, payload) {
			msg, err := a.decodeReport(report)
			if err == nil && msg != nil {
				Expect(msg.payload).To(Equal(payload))
				return
			}
		}
		Fail("message never completed")
	})

	It("refuses a continuation frame with no open message", func() {
		a := NewAuthenticator(nil, nil, nil)
		report := make([]byte, reportSize)
		report[4] = 0 // sequence frame
		_, err := a.decodeReport(report)
		Expect(err).To(HaveOccurred())
	})

	It("describes a report descriptor Chrome accepts", func() {
		Expect(reportDescriptor()).NotTo(BeEmpty())
	})
})

var _ = Describe("CTAPHID handshake", func() {
	It("allocates a channel and echoes the nonce", func() {
		_, writer, feeds, stop := newTestAuthenticator(&stubStore{}, denyGate{})
		defer stop()

		nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		for _, report := range buildRequest(broadcastChannel, cmdInit, nonce) {
			feeds.feedHostReport(report)
		}

		Eventually(writer.all, "3s").Should(HaveLen(1))
		reply := writer.all()[0]
		Expect(reply[4]).To(Equal(byte(cmdInit | typeInit)))
		payload := reply[7 : 7+17]
		Expect(payload[:8]).To(Equal(nonce))
		newCID := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])
		Expect(newCID).NotTo(Equal(uint32(broadcastChannel)))
		Expect(payload[12]).To(Equal(byte(2)))       // CTAPHID protocol version
		Expect(payload[16]).To(Equal(byte(capCBOR))) // CBOR capable, no wink
	})

	It("echoes ping payloads", func() {
		_, writer, feeds, stop := newTestAuthenticator(&stubStore{}, denyGate{})
		defer stop()

		// Allocate a channel first.
		for _, report := range buildRequest(broadcastChannel, cmdInit, make([]byte, 8)) {
			feeds.feedHostReport(report)
		}
		Eventually(writer.all, "3s").Should(HaveLen(1))
		cid := uint32(writer.all()[0][8])<<24 | uint32(writer.all()[0][9])<<16 | uint32(writer.all()[0][10])<<8 | uint32(writer.all()[0][11])

		payload := []byte("ping-data")
		for _, report := range buildRequest(cid, cmdPing, payload) {
			feeds.feedHostReport(report)
		}
		Eventually(func() [][]byte { return writer.all() }, "3s").Should(HaveLen(2))
		reply := writer.all()[1]
		Expect(reply[4]).To(Equal(byte(cmdPing | typeInit)))
		Expect(reply[7 : 7+len(payload)]).To(Equal(payload))
	})
})

var _ = Describe("CTAP2 commands", func() {
	allocate := func(writer *fakeWriter, feeds *fakeEvents) uint32 {
		for _, report := range buildRequest(broadcastChannel, cmdInit, make([]byte, 8)) {
			feeds.feedHostReport(report)
		}
		Eventually(writer.all, "3s").Should(HaveLen(1))
		reply := writer.all()[0]
		return uint32(reply[8])<<24 | uint32(reply[9])<<16 | uint32(reply[10])<<8 | uint32(reply[11])
	}

	sendCBOR := func(feeds *fakeEvents, cid uint32, command byte, body []byte) {
		for _, report := range buildRequest(cid, cmdCBOR, append([]byte{command}, body...)) {
			feeds.feedHostReport(report)
		}
	}

	It("answers GetInfo with the kpxcd capabilities", func() {
		_, writer, feeds, stop := newTestAuthenticator(&stubStore{creds: true}, allowGate{})
		defer stop()
		cid := allocate(writer, feeds)

		sendCBOR(feeds, cid, cmdGetInfo, nil)
		status, body := firstCBORReply(writer)
		Expect(status).To(Equal(statusOK))

		var info map[interface{}]interface{}
		Expect(cbor.Unmarshal(body, &info)).To(Succeed())
		info = normalizeMap(info)
		versions, _ := info[1].([]interface{})
		Expect(versions).To(ContainElement("FIDO_2_0"))
		aaguid, _ := info[3].([]byte)
		Expect(aaguid).To(Equal(aaguid[:]))
		// Chrome parses options at key 4 and maxMsgSize at key 5 (the
		// shipped CTAP2 layout); the options map must be there.
		options, ok := info[4].(map[interface{}]interface{})
		Expect(ok).To(BeTrue(), "options map at key 4")
		Expect(options["up"]).To(Equal(true))
		Expect(options["rk"]).To(Equal(true))
		Expect(options).NotTo(HaveKey("clientPin"), "clientPin omitted = not supported (D4)")
		_, ok = info[5].(uint64)
		Expect(ok).To(BeTrue(), "maxMsgSize unsigned at key 5")
		_, hasProtocols := info[6]
		Expect(hasProtocols).To(BeFalse(), "clientPin omitted means pinUvAuthProtocols omitted too (D4)")

		// Chrome's CBOR reader requires strictly monotonic map keys
		// (byte length, then byte-wise). The options map must appear
		// canonically ordered: rk, up (clientPin omitted = not supported).
		bodyHex := hex.EncodeToString(body)
		Expect(bodyHex).To(ContainSubstring("04a262726bf5627570f5"),
			"options map must be canonically ordered (rk, up)")
	})

	It("registers a credential when the gate approves", func() {
		store := &stubStore{}
		_, writer, feeds, stop := newTestAuthenticator(store, allowGate{})
		defer stop()
		cid := allocate(writer, feeds)

		req, err := cbor.Marshal(map[interface{}]interface{}{
			1: make([]byte, 32), // clientDataHash
			2: map[interface{}]interface{}{1: "example.com", 2: "Example"},
			3: map[interface{}]interface{}{1: []byte{9, 9}, 2: "user", 3: "User"},
			4: []interface{}{map[interface{}]interface{}{1: -7, 2: "public-key"}},
		})
		Expect(err).NotTo(HaveOccurred())
		sendCBOR(feeds, cid, cmdMakeCredential, req)

		status, body := firstCBORReply(writer)
		Expect(status).To(Equal(statusOK))
		var resp map[interface{}]interface{}
		Expect(cbor.Unmarshal(body, &resp)).To(Succeed())
		resp = normalizeMap(resp)
		Expect(resp[1]).To(Equal("none"))
		authData, _ := resp[2].([]byte)
		Expect(authData[32] & FlagUP).NotTo(Equal(byte(0)))
		Expect(authData[32] & FlagAT).NotTo(Equal(byte(0)))
		Expect(authData[37 : 37+16]).To(Equal(aaguid[:]))
		Expect(store.createCalls).To(Equal(1))
	})

	It("denies registration when the gate refuses", func() {
		_, writer, feeds, stop := newTestAuthenticator(&stubStore{}, denyGate{})
		defer stop()
		cid := allocate(writer, feeds)

		req, err := cbor.Marshal(map[interface{}]interface{}{
			1: make([]byte, 32),
			2: map[interface{}]interface{}{1: "example.com"},
			3: map[interface{}]interface{}{1: []byte{9}},
			4: []interface{}{map[interface{}]interface{}{1: -7, 2: "public-key"}},
		})
		Expect(err).NotTo(HaveOccurred())
		sendCBOR(feeds, cid, cmdMakeCredential, req)

		status, _ := firstCBORReply(writer)
		Expect(status).To(Equal(statusOperationDenied))
	})

	It("refuses algorithms outside the CTAP surface", func() {
		_, writer, feeds, stop := newTestAuthenticator(&stubStore{}, allowGate{})
		defer stop()
		cid := allocate(writer, feeds)

		req, err := cbor.Marshal(map[interface{}]interface{}{
			1: make([]byte, 32),
			2: map[interface{}]interface{}{1: "example.com"},
			3: map[interface{}]interface{}{1: []byte{9}},
			4: []interface{}{map[interface{}]interface{}{1: -8, 2: "public-key"}},
		})
		Expect(err).NotTo(HaveOccurred())
		sendCBOR(feeds, cid, cmdMakeCredential, req)

		status, _ := firstCBORReply(writer)
		Expect(status).To(Equal(statusUnsupportedAlgorithm))
	})

	It("answers no-credential assertions before any gate prompt", func() {
		store := &stubStore{creds: false}
		_, writer, feeds, stop := newTestAuthenticator(store, allowGate{})
		defer stop()
		cid := allocate(writer, feeds)

		req, err := cbor.Marshal(map[interface{}]interface{}{
			1: "unknown.example.com",
			2: make([]byte, 32),
		})
		Expect(err).NotTo(HaveOccurred())
		sendCBOR(feeds, cid, cmdGetAssertion, req)

		status, _ := firstCBORReply(writer)
		Expect(status).To(Equal(statusNoCredentials))
	})

	It("signs assertions for known credentials behind the gate", func() {
		store := &stubStore{creds: true}
		_, writer, feeds, stop := newTestAuthenticator(store, allowGate{})
		defer stop()
		cid := allocate(writer, feeds)

		req, err := cbor.Marshal(map[interface{}]interface{}{
			1: "example.com",
			2: make([]byte, 32),
		})
		Expect(err).NotTo(HaveOccurred())
		sendCBOR(feeds, cid, cmdGetAssertion, req)

		status, body := firstCBORReply(writer)
		Expect(status).To(Equal(statusOK))
		var resp map[interface{}]interface{}
		Expect(cbor.Unmarshal(body, &resp)).To(Succeed())
		resp = normalizeMap(resp)
		Expect(resp[1]).To(Equal([]byte{0xAA, 0xBB}))
		Expect(resp[3]).NotTo(BeEmpty())
	})

	It("refuses unknown CTAP2 commands", func() {
		_, writer, feeds, stop := newTestAuthenticator(&stubStore{}, allowGate{})
		defer stop()
		cid := allocate(writer, feeds)

		sendCBOR(feeds, cid, 0x41, nil)
		status, _ := firstCBORReply(writer)
		Expect(status).To(Equal(statusUnsupportedCommand))
	})
})

var _ = Describe("uhid event bridge", func() {
	It("strips Chromium's 0x00 report-ID prefix from writes", func() {
		// Reproduce the observed bytes: an INIT written with the 0x00
		// report-ID prefix Chromium adds for report-ID-less devices.
		chromeWrite := append([]byte{0x00}, buildRequest(broadcastChannel, cmdInit, []byte{9, 8, 7, 6, 5, 4, 3, 2})[0]...)
		Expect(chromeWrite).To(HaveLen(reportSize + 1))

		a := NewAuthenticator(nil, nil, nil)
		msg, err := a.decodeReport(chromeWrite[1 : 1+reportSize])
		Expect(err).NotTo(HaveOccurred())
		Expect(msg.command).To(Equal(byte(cmdInit)))
		Expect(msg.payload[:8]).To(Equal([]byte{9, 8, 7, 6, 5, 4, 3, 2}))
	})

	It("keeps plain 64-byte host reports as-is", func() {
		report := make([]byte, reportSize)
		copy(report[4:], []byte{0x86, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8})
		a := NewAuthenticator(nil, nil, nil)
		msg, err := a.decodeReport(report)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg.command).To(Equal(byte(cmdInit)))
	})
})
