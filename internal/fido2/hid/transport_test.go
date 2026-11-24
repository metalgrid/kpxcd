//go:build linux

package hid

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// blockingWriter stalls exactly the selected report, including its completion.
// Tests always release it in cleanup, even when an expectation fails.
type blockingWriter struct {
	fakeWriter
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	fail    bool
}

func (w *blockingWriter) writeReport(r []byte) error {
	w.once.Do(func() { close(w.entered); <-w.release })
	if w.fail {
		return errors.New("test: write failed")
	}
	return w.fakeWriter.writeReport(r)
}

type lateGate struct{ entered chan chan Approval }

func (g *lateGate) Approve(_ context.Context, _ Operation) Approval {
	result := make(chan Approval, 1)
	g.entered <- result
	return <-result // Deliberately violates cancellation to exercise late-result safety.
}

type blockedAssertionStore struct {
	stubStore
	entered chan struct{}
	release chan struct{}
}

func (s *blockedAssertionStore) AssertResident(ref CredentialReference, original []CredentialReference, hash []byte, up, uv bool) (ResidentAssertion, error) {
	return stubResidentAssertion(s, ref, hash, up, uv)
}

func (s *blockedAssertionStore) Assert(rp string, id, hash []byte, up, uv bool) ([]byte, []byte, []byte, []byte, error) {
	close(s.entered)
	<-s.release
	return s.stubStore.Assert(rp, id, hash, up, uv)
}

type transportStore struct {
	stubStore
	signs atomic.Int32
}

func (s *transportStore) AssertResident(ref CredentialReference, original []CredentialReference, hash []byte, up, uv bool) (ResidentAssertion, error) {
	return stubResidentAssertion(s, ref, hash, up, uv)
}

func (s *transportStore) Assert(rp string, id, hash []byte, up, uv bool) ([]byte, []byte, []byte, []byte, error) {
	s.signs.Add(1)
	return s.stubStore.Assert(rp, id, hash, up, uv)
}

var _ = Describe("Step 4 HID transport", func() {
	var a *Authenticator
	var writer *fakeWriter
	var ctx context.Context
	var cancel context.CancelFunc
	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		a = NewAuthenticator(&stubStore{creds: true}, allowGate{}, nil)
		a.channels[1], a.channels[2] = true, true
		writer = &fakeWriter{}
		a.writer = writer
	})
	AfterEach(func() { cancel(); a.Close() })
	feed := func(cid uint32, cmd byte, payload []byte) {
		for _, r := range buildRequest(cid, cmd, payload) {
			a.handleReport(ctx, r)
		}
	}
	idle := func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.owner == nil && !a.writing }
	waitIdle := func() { Eventually(idle, time.Second).Should(BeTrue()) }
	lastError := func(code byte) {
		Eventually(writer.all, time.Second).ShouldNot(BeEmpty())
		reports := writer.all()
		r := reports[len(reports)-1]
		Expect(r[4]).To(Equal(byte(0xbf)))
		Expect(r[7]).To(Equal(code))
	}
	assertion := func() []byte {
		b, err := marshalRequest(map[int]any{1: "example.com", 2: make([]byte, 32)})
		Expect(err).NotTo(HaveOccurred())
		return append([]byte{cmdGetAssertion}, b...)
	}

	DescribeTable("matches independently framed host packets in both directions", func(n int) {
		payload := bytes.Repeat([]byte{0x5a}, n)
		host := buildRequest(1, cmdPing, payload)
		device := encodeInitReply(1, cmdPing, payload)
		Expect(device).To(Equal(host))
		Expect(len(host)).To(Equal(1 + max(0, (n-57+58)/59)))
		for i, r := range device[1:] {
			Expect(int(r[4])).To(Equal(i))
		}
		if n == 7609 {
			Expect(device[128][4]).To(Equal(byte(127)))
		}
		for _, r := range host {
			a.handleReport(ctx, r)
		}
		Eventually(writer.all, time.Second).Should(Equal(host))
		waitIdle()
	}, Entry("zero", 0), Entry("57", 57), Entry("58", 58), Entry("116", 116), Entry("117", 117), Entry("352", 352), Entry("353", 353), Entry("1001", 1001), Entry("1002", 1002), Entry("1024", 1024), Entry("7609", 7609))

	It("rejects transport overflow independently of the CTAP limit", func() {
		r := buildRequest(1, cmdPing, nil)[0]
		r[5], r[6] = 0x1d, 0xba // 7610, one more than 7609.
		a.handleReport(ctx, r)
		lastError(0x03)
		Expect(encodeInitReply(1, cmdPing, make([]byte, 7610))).To(BeNil())
		Expect(a.reassembly).To(BeEmpty())
		writer = &fakeWriter{}
		a.writer = writer
		feed(1, cmdCBOR, bytes.Repeat([]byte{0}, 1025))
		Eventually(writer.all, time.Second).Should(HaveLen(1))
		Expect(writer.all()[0][4]).To(Equal(byte(0x90)))
		Expect(writer.all()[0][7]).To(Equal(byte(0x39)))
		waitIdle()
	})
	DescribeTable("rejects malformed report sizes without padding or truncation", func(n int) {
		r := make([]byte, n)
		if n >= 4 {
			binary.BigEndian.PutUint32(r, 1)
		}
		a.handleReport(ctx, r)
		if n < 4 {
			Expect(writer.all()).To(BeEmpty())
		} else {
			lastError(0x03)
		}
		Expect(a.reassembly).To(BeEmpty())
	}, Entry("empty", 0), Entry("CID truncated", 3), Entry("header truncated", 4), Entry("short", 63), Entry("long", 65), Entry("very long", 128))
	DescribeTable("rejects invalid channels without allocating state", func(cid uint32, cmd byte) {
		feed(cid, cmd, []byte{1})
		lastError(0x0b)
		Expect(a.reassembly).To(BeEmpty())
		Expect(a.channels).To(HaveLen(2))
	}, Entry("zero", uint32(0), byte(cmdPing)), Entry("unallocated", uint32(123456), byte(cmdPing)), Entry("unallocated INIT", uint32(123456), byte(cmdInit)), Entry("broadcast ping", uint32(0xffffffff), byte(cmdPing)))
	DescribeTable("validates fixed command lengths and unsupported capabilities", func(cmd byte, payload []byte, code byte) {
		feed(1, cmd, payload)
		lastError(code)
		Expect(a.reassembly).To(BeEmpty())
	}, Entry("short INIT", byte(cmdInit), make([]byte, 7), byte(3)), Entry("long INIT", byte(cmdInit), make([]byte, 9), byte(3)), Entry("empty CBOR", byte(cmdCBOR), []byte(nil), byte(3)), Entry("MSG", byte(cmdMsg), []byte{1}, byte(1)), Entry("WINK", byte(cmdWink), []byte(nil), byte(1)), Entry("LOCK", byte(4), []byte{1}, byte(1)), Entry("ERROR request", byte(cmdError), []byte{1}, byte(1)), Entry("KEEPALIVE request", byte(cmdKeepalive), []byte{1}, byte(1)))
	It("preserves nonce and CID semantics across repeated INIT", func() {
		for i := range 3 {
			nonce := bytes.Repeat([]byte{byte(i + 1)}, 8)
			feed(1, cmdInit, nonce)
			waitIdle()
			r := writer.all()[i]
			Expect(r[7:15]).To(Equal(nonce))
			Expect(binary.BigEndian.Uint32(r[15:19])).To(Equal(uint32(1)))
		}
		feed(broadcastChannel, cmdInit, []byte{8, 7, 6, 5, 4, 3, 2, 1})
		waitIdle()
		r := writer.all()[3]
		Expect(binary.BigEndian.Uint32(r[:4])).To(Equal(uint32(0xffffffff)))
		// These fixtures pre-allocated 1 and 2; production allocation starts empty.
		Expect(r[7:15]).To(Equal([]byte{8, 7, 6, 5, 4, 3, 2, 1}))
	})
	It("expires truncated reception and ignores late continuations", func() {
		a.receiveWait = 20 * time.Millisecond
		packets := buildRequest(1, cmdPing, make([]byte, 117))
		a.handleReport(ctx, packets[0])
		lastError(0x05)
		waitIdle()
		for _, r := range packets[1:] {
			a.handleReport(ctx, r)
		}
		Expect(writer.all()).To(HaveLen(1))
		feed(2, cmdPing, []byte{9})
		waitIdle()
		Expect(writer.all()).To(HaveLen(2))
	})
	It("invalidates an old receive timer after progress", func() {
		packets := buildRequest(1, cmdPing, make([]byte, 117))
		a.handleReport(ctx, packets[0])
		a.mu.Lock()
		op := a.owner
		old := op.receipt
		a.mu.Unlock()
		a.handleReport(ctx, packets[1])
		a.expireReceive(op, old)
		Expect(writer.all()).To(BeEmpty())
		a.handleReport(ctx, packets[2])
		waitIdle()
		Expect(writer.all()).To(HaveLen(3))
	})
	It("aborts an invalid sequence and never executes the old message", func() {
		packets := buildRequest(1, cmdPing, make([]byte, 117))
		a.handleReport(ctx, packets[0])
		packets[1][4] = 1
		a.handleReport(ctx, packets[1])
		lastError(4)
		waitIdle()
		a.handleReport(ctx, packets[2])
		Expect(writer.all()).To(HaveLen(1))
		feed(2, cmdPing, nil)
		waitIdle()
		Expect(writer.all()).To(HaveLen(2))
	})
	It("aborts malformed partial reception and does not extend its lifetime", func() {
		packets := buildRequest(1, cmdPing, make([]byte, 117))
		a.handleReport(ctx, packets[0])
		a.handleReport(ctx, packets[1][:63])
		lastError(3)
		waitIdle()
		a.handleReport(ctx, packets[1])
		a.handleReport(ctx, packets[2])
		Expect(writer.all()).To(HaveLen(1))
	})
	It("does not let same-channel commands or broadcast INIT replace reception", func() {
		p := buildRequest(1, cmdPing, make([]byte, 58))
		a.handleReport(ctx, p[0])
		feed(1, cmdPing, nil)
		lastError(6)
		feed(broadcastChannel, cmdInit, make([]byte, 8))
		lastError(6)
		a.handleReport(ctx, p[1])
		waitIdle()
		Expect(writer.all()).To(HaveLen(4))
	})
	It("keeps the transaction through a blocked final write and serializes busy errors", func() {
		w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
		a.writer = w
		release := sync.OnceFunc(func() { close(w.release) })
		defer release()
		payload := make([]byte, 353)
		feed(1, cmdPing, payload)
		Eventually(w.entered, time.Second).Should(BeClosed())
		Expect(idle()).To(BeFalse())
		finished := make(chan struct{})
		go func() { feed(2, cmdPing, nil); close(finished) }()
		Eventually(finished, time.Second).Should(BeClosed())
		Expect(w.all()).To(BeEmpty())
		release()
		Eventually(finished, time.Second).Should(BeClosed())
		waitIdle()
		reports := w.all()
		Expect(reports).To(HaveLen(8))
		Expect(reports[:7]).To(Equal(buildRequest(1, cmdPing, payload)))
		Expect(reports[7][4]).To(Equal(byte(0xbf)))
		Expect(reports[7][7]).To(Equal(byte(6)))
	})
	DescribeTable("releases failed output or shutdown without deadlocking", func(shutdown bool) {
		w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{}), fail: !shutdown}
		a.writer = w
		release := sync.OnceFunc(func() { close(w.release) })
		defer release()
		feed(1, cmdPing, make([]byte, 353))
		Eventually(w.entered, time.Second).Should(BeClosed())
		if shutdown {
			a.Close()
			a.mu.Lock()
			Expect(a.owner).To(BeNil())
			a.mu.Unlock()
		}
		release()
		waitIdle()
		if shutdown {
			feed(2, cmdPing, nil)
			Eventually(w.all, time.Second).Should(HaveLen(1))
		} else {
			a.writer = writer
			feed(2, cmdPing, nil)
			waitIdle()
			Expect(writer.all()).To(HaveLen(1))
		}
	}, Entry("failed write", false), Entry("shutdown", true))
	It("resynchronizes during blocked output and suppresses remaining obsolete fragments", func() {
		w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
		a.writer = w
		release := sync.OnceFunc(func() { close(w.release) })
		defer release()
		feed(1, cmdPing, make([]byte, 353))
		Eventually(w.entered, time.Second).Should(BeClosed())
		nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		for range 100 {
			feed(1, cmdInit, nonce)
		}
		a.mu.Lock()
		Expect(a.output).To(HaveLen(1))
		a.mu.Unlock()
		release()
		waitIdle()
		Expect(w.all()).To(HaveLen(2))
		Expect(w.all()[1][4]).To(Equal(byte(0x86)))
		Expect(w.all()[1][7:15]).To(Equal(nonce))
	})
	It("keeps the receive loop responsive to INIT behind a queued busy error", func() {
		w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
		a.writer = w
		release := sync.OnceFunc(func() { close(w.release) })
		defer release()
		events := make(chan event, 4)
		a.events = events
		loopDone := make(chan struct{})
		go func() { a.run(ctx); close(loopDone) }()
		defer func() { cancel(); Eventually(loopDone, time.Second).Should(BeClosed()) }()
		events <- event{isHostReport: true, report: buildRequest(1, cmdPing, make([]byte, 353))[0]}
		// Complete host reception before waiting for the blocked response.
		for _, r := range buildRequest(1, cmdPing, make([]byte, 353))[1:] {
			events <- event{isHostReport: true, report: r}
		}
		Eventually(w.entered, time.Second).Should(BeClosed())
		events <- event{isHostReport: true, report: buildRequest(2, cmdPing, nil)[0]}
		events <- event{isHostReport: true, report: buildRequest(1, cmdInit, make([]byte, 8))[0]}
		Eventually(func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.owner != nil && a.owner.command == cmdInit }, time.Second).Should(BeTrue())
		release()
		waitIdle()
		Expect(w.all()).To(HaveLen(3))
		Expect(w.all()[0][4]).To(Equal(byte(0x81)))
		Expect(w.all()[1][4]).To(Equal(byte(0xbf)))
		Expect(w.all()[2][4]).To(Equal(byte(0x86)))
	})
	It("bounds pending output and fails closed when a stalled sink is flooded", func() {
		w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
		a.writer = w
		release := sync.OnceFunc(func() { close(w.release) })
		defer release()
		feed(1, cmdPing, nil)
		Eventually(w.entered, time.Second).Should(BeClosed())
		for range maxPendingOutput + 1 {
			feed(2, cmdPing, nil)
		}
		a.mu.Lock()
		Expect(a.stopped).To(BeTrue())
		Expect(a.output).To(BeEmpty())
		Expect(a.owner).To(BeNil())
		a.mu.Unlock()
		release()
		waitIdle()
		Expect(w.all()).To(HaveLen(1))
	})
	It("coalesces queued keepalives and suppresses them after shutdown", func() {
		w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
		a.writer = w
		release := sync.OnceFunc(func() { close(w.release) })
		defer release()
		g := &lateGate{entered: make(chan chan Approval, 1)}
		a.gate = g
		feed(1, cmdCBOR, assertion())
		var result chan Approval
		Eventually(g.entered, time.Second).Should(Receive(&result))
		a.mu.Lock()
		op := a.owner
		a.mu.Unlock()
		a.keepalive(op)
		Eventually(w.entered, time.Second).Should(BeClosed())
		for range 100 {
			a.keepalive(op)
		}
		a.mu.Lock()
		Expect(a.output).To(HaveLen(1))
		Expect(a.stopped).To(BeFalse())
		a.mu.Unlock()
		a.Close()
		result <- Approval{Approved: true, UserPresence: true, UserVerification: true}
		release()
		Eventually(op.done, time.Second).Should(BeClosed())
		waitIdle()
		Expect(w.all()).To(HaveLen(1))
	})
	It("discards a late store signature after resync without claiming to undo persistence", func() {
		s := &blockedAssertionStore{stubStore: stubStore{creds: true}, entered: make(chan struct{}), release: make(chan struct{})}
		a.store = s
		release := sync.OnceFunc(func() { close(s.release) })
		defer release()
		feed(1, cmdCBOR, assertion())
		Eventually(s.entered, time.Second).Should(BeClosed())
		a.mu.Lock()
		old := a.inflight[1]
		a.mu.Unlock()
		feed(1, cmdInit, make([]byte, 8))
		waitIdle()
		release()
		Eventually(old.done, time.Second).Should(BeClosed())
		Expect(writer.all()).To(HaveLen(1))
		Expect(writer.all()[0][4]).To(Equal(byte(0x86)))
	})
	It("ignores nonzero final report padding rather than appending it", func() {
		payload := bytes.Repeat([]byte{0x42}, 1002)
		packets := buildRequest(1, cmdPing, payload)
		last := packets[len(packets)-1]
		used := (1002 - 57) % 59
		for i := 5 + used; i < 64; i++ {
			last[i] = 0xff
		}
		for _, r := range packets {
			a.handleReport(ctx, r)
		}
		waitIdle()
		Expect(writer.all()).To(Equal(buildRequest(1, cmdPing, payload)))
	})
	It("ignores CANCEL on every non-active CID, including reserved and unallocated CIDs", func() {
		for _, cid := range []uint32{0, 1, 2, 12345, broadcastChannel} {
			feed(cid, cmdCancel, nil)
		}
		Expect(writer.all()).To(BeEmpty())
	})
	It("allocates distinct nonreserved CIDs only through broadcast INIT", func() {
		a.channels = make(map[uint32]bool)
		for i := range 3 {
			feed(broadcastChannel, cmdInit, bytes.Repeat([]byte{byte(i)}, 8))
			waitIdle()
			r := writer.all()[i]
			Expect(binary.BigEndian.Uint32(r[15:19])).To(Equal(uint32(i + 1)))
		}
		Expect(a.channels).To(HaveLen(3))
	})
	It("suppresses a canceled old response and keepalives after INIT while the writer is blocked", func() {
		w := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
		a.writer = w
		release := sync.OnceFunc(func() { close(w.release) })
		defer release()
		g := &lateGate{entered: make(chan chan Approval, 1)}
		a.gate = g
		s := &transportStore{stubStore: stubStore{creds: true}}
		a.store = s
		feed(1, cmdCBOR, assertion())
		var result chan Approval
		Eventually(g.entered, time.Second).Should(Receive(&result))
		Eventually(w.entered, time.Second).Should(BeClosed()) // Old keepalive entered the sink.
		a.mu.Lock()
		old := a.inflight[1]
		a.mu.Unlock()
		feed(1, cmdCancel, nil)
		feed(1, cmdInit, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		result <- Approval{Approved: true, UserPresence: true, UserVerification: true}
		release()
		Eventually(old.done, time.Second).Should(BeClosed())
		waitIdle()
		Expect(s.signs.Load()).To(BeZero())
		Expect(w.all()).To(HaveLen(2)) // Only the already-entered keepalive and the INIT reply.
		Expect(w.all()[0][4]).To(Equal(byte(0xbb)))
		Expect(w.all()[1][4]).To(Equal(byte(0x86)))
	})
	It("binds cancellation to its operation and requires fresh approval after resync", func() {
		g := &lateGate{entered: make(chan chan Approval, 2)}
		a.gate = g
		s := &transportStore{stubStore: stubStore{creds: true}}
		a.store = s
		feed(1, cmdCBOR, assertion())
		var first chan Approval
		Eventually(g.entered, time.Second).Should(Receive(&first))
		a.mu.Lock()
		old := a.inflight[1]
		a.mu.Unlock()
		feed(2, cmdCancel, nil)
		feed(1, cmdCancel, []byte{1})
		a.mu.Lock()
		Expect(old.cancelRequested).To(BeFalse())
		a.mu.Unlock()
		feed(1, cmdCancel, nil)
		Eventually(old.done, time.Second).Should(BeClosed())
		waitIdle()
		Expect(writer.all()[len(writer.all())-1][7]).To(Equal(byte(0x2d)))
		feed(1, cmdInit, make([]byte, 8))
		waitIdle()
		first <- Approval{Approved: true, UserPresence: true, UserVerification: true}
		feed(1, cmdCBOR, assertion())
		var second chan Approval
		Eventually(g.entered, time.Second).Should(Receive(&second))
		Expect(s.signs.Load()).To(BeZero())
		a.mu.Lock()
		current := a.inflight[1]
		a.mu.Unlock()
		feed(1, cmdInit, make([]byte, 8))
		waitIdle()
		Eventually(current.done, time.Second).Should(BeClosed())
		second <- Approval{Approved: true, UserPresence: true, UserVerification: true}
		Consistently(s.signs.Load, 30*time.Millisecond).Should(BeZero())
		for _, r := range writer.all() {
			if r[4] == 0x90 {
				Expect(r[7]).To(Equal(byte(0x2d)))
			}
		}
	})
})
