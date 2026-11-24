//go:build linux

package hid

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type residentTestStore struct {
	stubStore
	mu               sync.Mutex
	refs             []CredentialReference
	signed           []CredentialReference
	hashes           [][]byte
	fail             bool
	resident         bool
	entered, release chan struct{}
}

func (s *residentTestStore) Create(rp, rpName, name, display string, id []byte, resident bool) ([]byte, []byte, []byte, error) {
	s.resident = resident
	return s.stubStore.Create(rp, rpName, name, display, id, resident)
}
func (s *residentTestStore) ResidentCredentials(rp string) ([]CredentialReference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.refs), nil
}
func (s *residentTestStore) AssertResident(ref CredentialReference, original []CredentialReference, hash []byte, up, uv bool) (ResidentAssertion, error) {
	if s.entered != nil {
		s.entered <- struct{}{}
		select {
		case <-s.release:
		case <-time.After(5 * time.Second):
			return ResidentAssertion{}, errors.New("test release timed out")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail || !slices.Contains(s.refs, ref) || slices.ContainsFunc(original, func(candidate CredentialReference) bool { return !slices.Contains(s.refs, candidate) }) {
		return ResidentAssertion{}, errors.New("candidate unavailable")
	}
	s.signed = append(s.signed, ref)
	s.hashes = append(s.hashes, slices.Clone(hash))
	flags := byte(0)
	if up {
		flags |= FlagUP
	}
	if uv {
		flags |= FlagUV
	}
	// Deliberately supply names even without UV, to test command-layer privacy.
	return ResidentAssertion{CredentialID: []byte(ref.CredentialID), UserHandle: []byte(ref.UserHandle), AuthData: authenticatorData(ref.RPID, flags, 1, nil), Signature: []byte{1}, Name: "alice", DisplayName: "Alice"}, nil
}

var _ = Describe("Step 5 resident commands", func() {
	var a *Authenticator
	var store *residentTestStore
	var ctx context.Context
	var writer *fakeWriter
	var gate *countedGate
	request := func(options map[string]any, list []any) []byte {
		req := map[int]any{1: "example.com", 2: make([]byte, 32)}
		if options != nil {
			req[5] = options
		}
		if list != nil {
			req[3] = list
		}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		return body
	}
	decode := func(body []byte) map[uint64]any {
		var result map[uint64]any
		Expect(cbor.Unmarshal(body, &result)).To(Succeed())
		return result
	}
	start := func(options map[string]any) map[uint64]any {
		status, body := a.runCommand(ctx, cmdGetAssertion, request(options, nil), 1)
		Expect(status).To(Equal(statusOK))
		return decode(body)
	}
	pending := func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.pending != nil }
	idle := func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.owner == nil && !a.writing }
	feed := func(cid uint32, command byte, body []byte) {
		for _, report := range buildRequest(cid, command, body) {
			a.handleReport(ctx, report)
		}
		Eventually(idle, time.Second).Should(BeTrue())
	}
	BeforeEach(func() {
		ctx = context.Background()
		gate = &countedGate{approved: true}
		store = &residentTestStore{stubStore: stubStore{creds: true}, refs: []CredentialReference{{DatabaseUUID: "db", DatabaseInstance: 1, EntryUUID: "new", RPID: "example.com", CredentialID: "new", UserHandle: "one"}, {DatabaseUUID: "db", DatabaseInstance: 1, EntryUUID: "old", RPID: "example.com", CredentialID: "old", UserHandle: "two"}, {DatabaseUUID: "db", DatabaseInstance: 1, EntryUUID: "oldest", RPID: "example.com", CredentialID: "oldest", UserHandle: "three"}}}
		a = NewAuthenticator(store, gate, nil)
		writer = &fakeWriter{}
		a.writer = writer
		a.channels[1], a.channels[2] = true, true
	})
	AfterEach(func() { a.Close() })
	It("returns all resident accounts with one approval and no count on continuations", func() {
		first := start(nil)
		Expect(first[5]).To(Equal(uint64(3)))
		Expect(int(gate.calls.Load())).To(Equal(1))
		Expect(pending()).To(BeTrue())
		for range 2 {
			status, body := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
			Expect(status).To(Equal(statusOK))
			Expect(decode(body)).NotTo(HaveKey(uint64(5)))
		}
		Expect(store.signed).To(Equal(store.refs))
		Expect(store.hashes).To(Equal([][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)}))
		Expect(int(gate.calls.Load())).To(Equal(1))
		Expect(pending()).To(BeFalse())
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusNotAllowed))
		Expect(store.signed).To(HaveLen(3))
	})
	DescribeTable("never discloses names without actual UV", func(uv bool) {
		a.gate = verdictGate{Approval{Approved: true, UserPresence: true, UserVerification: uv}}
		for i := 0; i < 3; i++ {
			var result map[uint64]any
			if i == 0 {
				result = start(nil)
			} else {
				status, body := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
				Expect(status).To(Equal(statusOK))
				result = decode(body)
			}
			user := result[4].(map[any]any)
			Expect(user["id"]).NotTo(BeEmpty())
			if uv {
				Expect(user["name"]).To(Equal("alice"))
				Expect(user["displayName"]).To(Equal("Alice"))
			} else {
				Expect(user).NotTo(HaveKey("name"))
				Expect(user).NotTo(HaveKey("displayName"))
			}
		}
	}, Entry("unverified", false), Entry("verified", true))
	It("omits count and pending state for a single resident account", func() {
		store.refs = store.refs[:1]
		Expect(start(nil)).NotTo(HaveKey(uint64(5)))
		Expect(pending()).To(BeFalse())
	})
	It("does not enumerate a nonempty allow-list", func() {
		status, body := a.runCommand(ctx, cmdGetAssertion, request(nil, []any{map[string]any{"type": "public-key", "id": []byte{0xaa, 0xbb}}}), 1)
		Expect(status).To(Equal(statusOK))
		Expect(decode(body)).NotTo(HaveKey(uint64(5)))
		Expect(pending()).To(BeFalse())
		Expect(store.signed).To(BeEmpty())
	})
	It("treats an empty allow-list as resident lookup", func() {
		status, body := a.runCommand(ctx, cmdGetAssertion, request(nil, []any{}), 1)
		Expect(status).To(Equal(statusOK))
		Expect(decode(body)[5]).To(Equal(uint64(3)))
	})
	It("expires only after more than thirty seconds and resets time on each success", func() {
		start(nil)
		a.mu.Lock()
		a.pending.lastSuccess = time.Now().Add(-29 * time.Second)
		before := a.pending.lastSuccess
		a.mu.Unlock()
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusOK))
		a.mu.Lock()
		Expect(a.pending.lastSuccess.After(before)).To(BeTrue())
		a.pending.lastSuccess = time.Now().Add(-31 * time.Second)
		a.mu.Unlock()
		status, _ = a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusNotAllowed))
		Expect(store.signed).To(HaveLen(2))
		Expect(pending()).To(BeFalse())
	})
	DescribeTable("clears unavailable original candidates without advancing any counter", func(which int) {
		start(nil)
		store.refs = append(slices.Clone(store.refs[:which]), store.refs[which+1:]...)
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusNotAllowed))
		Expect(store.signed).To(HaveLen(1))
		Expect(pending()).To(BeFalse())
	}, Entry("already returned credential locked", 0), Entry("next credential removed", 1), Entry("later credential replaced", 2))
	DescribeTable("refuses a nonselected change after the HID snapshot but before authoritative signing", func(which int) {
		start(nil)
		store.entered = make(chan struct{}, 1)
		store.release = make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(store.release) }) }
		defer unblock()
		done := make(chan byte, 1)
		go func() {
			status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
			done <- status
		}()
		Eventually(store.entered, time.Second).Should(Receive())
		store.mu.Lock()
		selected := store.refs[1]
		store.refs = append(slices.Clone(store.refs[:which]), store.refs[which+1:]...)
		Expect(slices.Contains(store.refs, selected)).To(BeTrue())
		store.mu.Unlock()
		unblock()
		Eventually(done, time.Second).Should(Receive(Equal(statusNotAllowed)))
		Expect(store.signed).To(HaveLen(1))
		Expect(pending()).To(BeFalse())
	}, Entry("already returned", 0), Entry("later", 2))
	It("clears state after authoritative targeted assertion refusal", func() {
		start(nil)
		store.fail = true
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusNotAllowed))
		Expect(store.signed).To(HaveLen(1))
		Expect(pending()).To(BeFalse())
	})
	It("binds continuation to its CID and clears on another CID", func() {
		start(nil)
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 2)
		Expect(status).To(Equal(statusNotAllowed))
		status, _ = a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusNotAllowed))
		Expect(store.signed).To(HaveLen(1))
	})
	DescribeTable("rejects arguments rather than treating them as another approval", func(data []byte) {
		start(nil)
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, data, 1)
		Expect(status).To(Equal(statusInvalidLength))
		Expect(pending()).To(BeFalse())
		Expect(int(gate.calls.Load())).To(Equal(1))
		Expect(store.signed).To(HaveLen(1))
	}, Entry("empty map", []byte{0xa0}), Entry("null", []byte{0xf6}))
	DescribeTable("clears pending authorization on unrelated CTAP commands", func(command byte) {
		start(nil)
		a.runCommand(ctx, command, nil, 1)
		Expect(pending()).To(BeFalse())
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusNotAllowed))
	}, Entry("GetInfo", byte(cmdGetInfo)), Entry("MakeCredential", byte(cmdMakeCredential)), Entry("unknown", byte(0x55)), Entry("new GetAssertion", byte(cmdGetAssertion)))
	It("requires fresh approval for a new GetAssertion", func() {
		start(nil)
		start(nil)
		Expect(int(gate.calls.Load())).To(Equal(2))
		Expect(store.signed).To(HaveLen(2))
	})
	It("preserves pending assertions across normal successful wire transaction completion", func() {
		feed(1, cmdCBOR, append([]byte{cmdGetAssertion}, request(nil, nil)...))
		Expect(pending()).To(BeTrue())
		Expect(store.signed).To(HaveLen(1))
		feed(1, cmdCBOR, []byte{cmdGetNextAssertion})
		Expect(pending()).To(BeTrue())
		Expect(store.signed).To(HaveLen(2))
		Expect(int(gate.calls.Load())).To(Equal(1))
	})
	DescribeTable("clears pending state on accepted HID lifecycle commands", func(command byte) {
		start(nil)
		var payload []byte
		if command == cmdInit {
			payload = make([]byte, 8)
		}
		feed(1, command, payload)
		Expect(pending()).To(BeFalse())
		status, _ := a.runCommand(ctx, cmdGetNextAssertion, nil, 1)
		Expect(status).To(Equal(statusNotAllowed))
	}, Entry("resync", byte(cmdInit)), Entry("PING", byte(cmdPing)))
	It("clears pending state on close", func() { start(nil); a.Close(); Expect(pending()).To(BeFalse()) })
	It("does not restore continuation authorization after resync during a slow assertion", func() {
		start(nil)
		store.entered = make(chan struct{}, 1)
		store.release = make(chan struct{})
		defer close(store.release)
		for _, report := range buildRequest(1, cmdCBOR, []byte{cmdGetNextAssertion}) {
			a.handleReport(ctx, report)
		}
		Eventually(store.entered, time.Second).Should(Receive())
		a.mu.Lock()
		old := a.owner
		a.mu.Unlock()
		feed(1, cmdInit, make([]byte, 8))
		Expect(pending()).To(BeFalse())
		store.release <- struct{}{}
		Eventually(old.done, time.Second).Should(BeClosed())
		Expect(pending()).To(BeFalse())
	})
	It("clears pending state on cancellation of an active continuation", func() {
		start(nil)
		store.entered = make(chan struct{}, 1)
		store.release = make(chan struct{})
		defer close(store.release)
		for _, report := range buildRequest(1, cmdCBOR, []byte{cmdGetNextAssertion}) {
			a.handleReport(ctx, report)
		}
		Eventually(store.entered, time.Second).Should(Receive())
		a.handleReport(ctx, buildRequest(1, cmdCancel, nil)[0])
		Expect(pending()).To(BeFalse())
		store.release <- struct{}{}
		Eventually(idle, time.Second).Should(BeTrue())
	})
	DescribeTable("forwards only explicit true resident intent to creation", func(options map[string]any, want bool) {
		body, err := marshalRequest(map[int]any{1: make([]byte, 32), 2: map[string]any{"id": "example.com"}, 3: map[string]any{"id": []byte{0}}, 4: []any{map[string]any{"alg": -7, "type": "public-key"}}, 7: options})
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.runCommand(ctx, cmdMakeCredential, body, 1)
		Expect(status).To(Equal(statusOK))
		Expect(store.resident).To(Equal(want))
	}, Entry("true", map[string]any{"rk": true}, true), Entry("false", map[string]any{"rk": false}, false), Entry("absent", map[string]any{}, false))
})
