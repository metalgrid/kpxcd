//go:build linux

package hid

import (
	"context"
	"encoding/hex"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type countedGate struct {
	calls    atomic.Int32
	approved bool
}

func (g *countedGate) Approve(context.Context, Operation) Approval {
	g.calls.Add(1)
	return Approval{Approved: g.approved, UserPresence: true, UserVerification: true}
}

type observedPendingGate struct{ entered chan struct{} }

func (g observedPendingGate) Approve(ctx context.Context, _ Operation) Approval {
	close(g.entered)
	<-ctx.Done()
	return Approval{}
}

var _ = Describe("conformance baseline", func() {
	DescribeTable("numbers every continuation before narrowing the sequence",
		func(length int) {
			reports := encodeInitReply(1, cmdCBOR, make([]byte, length))
			for i, report := range reports[1:] {
				Expect(report[4]).To(Equal(byte(i)))
			}
		}, Entry("352", 352), Entry("353", 353), Entry("1024", 1024))
	DescribeTable("ignores report padding beyond the declared message length",
		func(length int) {
			a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
			a.writer = &fakeWriter{}
			var msg *hostMessage
			for _, report := range buildRequest(1, cmdCBOR, make([]byte, length)) {
				var err error
				msg, err = a.decodeReport(report)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(msg).NotTo(BeNil())
			Expect(msg.payload).To(HaveLen(length))
		}, Entry("1001", 1001), Entry("1002", 1002), Entry("1024", 1024))
	It("rejects duplicate CBOR keys (decoder SHOULD)", func() {
		_, err := decodeRequest([]byte{0xa2, 0x01, 0x01, 0x01, 0x02})
		Expect(err).To(HaveOccurred())
	})
	It("uses the product AAGUID in attested credential data", func() {
		data, err := attestedCredentialData([]byte{1}, []byte{0xa0})
		Expect(err).NotTo(HaveOccurred())
		Expect(hex.EncodeToString(data[:16])).To(Equal("ab449b5ed0bf4d8d81b1de5ec1a8c00e"))
	})
	It("advertises only implemented credential generation algorithms", func() {
		Expect(getInfoAlgorithms).To(Equal([]getInfoAlgorithm{{Alg: -7, Type: "public-key"}}))
	})
	It("requires clientDataHash before creating a credential", func() {
		store := &stubStore{}
		a := NewAuthenticator(store, allowGate{}, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(map[int]any{2: map[string]any{"id": "example.com"}, 3: map[string]any{"id": []byte{1}}, 4: []any{map[string]any{"type": "public-key", "alg": -7}}})
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(statusMissingParam))
		Expect(store.createCalls).To(BeZero())
	})
	It("tries a matching later allow-list credential", func() {
		a := NewAuthenticator(&stubStore{creds: true}, allowGate{}, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(map[int]any{1: "example.com", 2: make([]byte, 32), 3: []any{map[string]any{"type": "public-key", "id": []byte{0xff}}, map[string]any{"type": "public-key", "id": []byte{0xaa, 0xbb}}}})
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(statusOK))
	})
	It("discards partial reception when INIT resynchronizes a channel", func() {
		a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
		a.writer = &fakeWriter{}
		a.channels[1] = true
		reports := buildRequest(1, cmdPing, make([]byte, 100))
		a.handleReport(context.Background(), reports[0])
		a.mu.Lock()
		Expect(a.reassembly).To(HaveKey(uint32(1)))
		a.mu.Unlock()
		a.handleReport(context.Background(), buildRequest(1, cmdInit, make([]byte, 8))[0])
		a.mu.Lock()
		Expect(a.reassembly).NotTo(HaveKey(uint32(1)))
		a.mu.Unlock()
	})
	DescribeTable("does not disclose an excluded credential before consent",
		func(approved bool, expected byte) {
			gate := &countedGate{approved: approved}
			store := &stubStore{excluded: true}
			a := NewAuthenticator(store, gate, nil)
			a.writer = &fakeWriter{}
			body, err := marshalRequest(map[int]any{1: make([]byte, 32), 2: map[string]any{"id": "example.com"}, 3: map[string]any{"id": []byte{1}}, 4: []any{map[string]any{"type": "public-key", "alg": -7}}, 5: []any{map[string]any{"type": "public-key", "id": []byte{0xaa, 0xbb}}}})
			Expect(err).NotTo(HaveOccurred())
			status, _ := a.makeCredential(context.Background(), body, 1)
			Expect(gate.calls.Load()).To(Equal(int32(1)), "exclusion requires consent before returning")
			Expect(status).To(Equal(expected))
			Expect(store.createCalls).To(BeZero())
		}, Entry("denied consent", false, statusOperationDenied), Entry("approved consent", true, statusCredentialExcluded))
	It("rejects the known up option for MakeCredential even when true", func() {
		store := &stubStore{}
		a := NewAuthenticator(store, allowGate{}, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(map[int]any{1: make([]byte, 32), 2: map[string]any{"id": "example.com"}, 3: map[string]any{"id": []byte{1}}, 4: []any{map[string]any{"type": "public-key", "alg": -7}}, 7: map[string]any{"up": true}})
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(byte(0x2c)), "CTAP2_ERR_INVALID_OPTION")
		Expect(store.createCalls).To(BeZero())
	})
	It("rejects reserved channel zero", func() {
		a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
		writer := &fakeWriter{}
		a.writer = writer
		a.handleReport(context.Background(), buildRequest(0, cmdPing, []byte{1})[0])
		Eventually(writer.all, time.Second).Should(HaveLen(1))
		Expect(writer.all()[0][4]).To(Equal(byte(cmdError | 0x80)))
		Expect(writer.all()[0][7]).To(Equal(byte(0x0b)), "ERR_INVALID_CHANNEL")
	})
	It("keeps receive ownership across channels until the partial request completes", func() {
		a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
		writer := &fakeWriter{}
		a.writer = writer
		a.channels[1], a.channels[2] = true, true
		a.handleReport(context.Background(), buildRequest(1, cmdPing, make([]byte, 100))[0])
		a.handleReport(context.Background(), buildRequest(2, cmdPing, []byte{1})[0])
		Eventually(writer.all, time.Second).Should(HaveLen(1))
		Expect(writer.all()[0][4]).To(Equal(byte(cmdError | 0x80)))
		Expect(writer.all()[0][7]).To(Equal(byte(0x06)), "ERR_CHANNEL_BUSY")
	})
	It("keeps approval ownership across channels with a bounded pending gate", func() {
		gate := observedPendingGate{entered: make(chan struct{})}
		a := NewAuthenticator(&stubStore{creds: true}, gate, nil)
		writer := &fakeWriter{}
		a.writer = writer
		a.channels[1], a.channels[2] = true, true
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		body, err := marshalRequest(map[int]any{1: "example.com", 2: make([]byte, 32)})
		Expect(err).NotTo(HaveOccurred())
		a.handleMessage(ctx, &hostMessage{channelID: 1, command: cmdCBOR, payload: append([]byte{cmdGetAssertion}, body...)})
		a.mu.Lock()
		op := a.inflight[1]
		a.mu.Unlock()
		defer func() { cancel(); Eventually(op.done, 2*time.Second).Should(BeClosed()) }()
		Eventually(gate.entered, time.Second).Should(BeClosed())
		a.handleReport(ctx, buildRequest(2, cmdPing, []byte{1})[0])
		Eventually(writer.all, time.Second).ShouldNot(BeEmpty())
		reports := writer.all()
		Expect(reports).NotTo(BeEmpty())
		Expect(reports[0][4]).To(Equal(byte(cmdError | 0x80)))
		Expect(reports[0][7]).To(Equal(byte(0x06)))
	})
	It("rejects incorrectly typed known options", func() {
		a := NewAuthenticator(&stubStore{creds: true}, allowGate{}, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(map[int]any{1: "example.com", 2: make([]byte, 32), 5: map[string]any{"uv": "true"}})
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.getAssertion(context.Background(), body, 1)
		Expect(status).NotTo(Equal(statusOK))
	})
})
