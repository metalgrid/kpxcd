//go:build linux

package hid

import (
	"context"
	"encoding/hex"

	"github.com/fxamacker/cbor/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type verdictGate struct{ result Approval }

func (g verdictGate) Approve(context.Context, Operation) Approval { return g.result }

var _ = Describe("Step 3 actual approval results", func() {
	DescribeTable("uses all established checks rather than the requested subset", func(up, uv bool) {
		gate := verdictGate{Approval{Approved: true, UserPresence: true, UserVerification: true}}
		store := &identityStore{stubStore: stubStore{creds: true}}
		a := NewAuthenticator(store, gate, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(map[int]any{1: "example.com", 2: make([]byte, 32), 5: map[string]any{"up": up, "uv": uv}})
		Expect(err).NotTo(HaveOccurred())
		status, response := a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(statusOK))
		var assertion getAssertionResponse
		Expect(cbor.Unmarshal(response, &assertion)).To(Succeed())
		flags := byte(0)
		if up || uv {
			flags = FlagUP | FlagUV
		}
		Expect(assertion.AuthData[32]).To(Equal(flags))
		req := validRegistration()
		req[7] = map[string]any{"uv": uv}
		body, err = marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, response = a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(statusOK))
		var registration makeCredentialResponse
		Expect(cbor.Unmarshal(response, &registration)).To(Succeed())
		Expect(registration.AuthData[32]).To(Equal(byte(FlagUP | FlagUV | FlagAT)))
	}, Entry("UP only request", true, false), Entry("UV only request", false, true), Entry("both requested", true, true), Entry("silent skips even a combined gate", false, false))
	DescribeTable("denies incomplete or denied checks without signing or creation", func(result Approval) {
		store := &identityStore{stubStore: stubStore{creds: true}}
		a := NewAuthenticator(store, verdictGate{result}, nil)
		a.writer = &fakeWriter{}
		for _, command := range []byte{cmdMakeCredential, cmdGetAssertion} {
			req := validRegistration()
			req[7] = map[string]any{"uv": true}
			if command == cmdGetAssertion {
				req = map[int]any{1: "example.com", 2: make([]byte, 32), 5: map[string]any{"uv": true}}
			}
			body, err := marshalRequest(req)
			Expect(err).NotTo(HaveOccurred())
			status, response := a.runCommand(context.Background(), command, body, 1)
			Expect(status).To(Equal(statusOperationDenied))
			Expect(response).To(BeNil())
		}
		Expect(store.createCalls).To(BeZero())
		Expect(store.asserted).To(BeEmpty())
		result, _ = a.waitGate(context.Background(), 1, Operation{UserPresence: true, UserVerification: true})
		Expect(result).To(Equal(Approval{}))
	}, Entry("zero", Approval{}), Entry("approved without checks", Approval{Approved: true}), Entry("missing verification", Approval{Approved: true, UserPresence: true}), Entry("missing presence", Approval{Approved: true, UserVerification: true}), Entry("denied with partial checks", Approval{UserPresence: true, UserVerification: true}))
	It("discards even a successful late result after cancellation", func() {
		a := NewAuthenticator(&stubStore{}, verdictGate{Approval{Approved: true, UserPresence: true, UserVerification: true}}, nil)
		a.writer = &fakeWriter{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, _ := a.waitGate(ctx, 1, Operation{UserPresence: true})
		Expect(result).To(Equal(Approval{}))
	})
})

var _ = Describe("Step 3 primitive integer key boundaries", func() {
	It("safely refuses truncated boundary fixtures and arbitrary single-byte inputs", func() {
		fixture, err := hex.DecodeString("a21863003bffffffffffffffff00")
		Expect(err).NotTo(HaveOccurred())
		for length := range len(fixture) {
			_, err := decodeRequest(fixture[:length])
			Expect(err).To(HaveOccurred())
		}
		for value := range 256 {
			Expect(func() { _, _ = decodeRequest([]byte{byte(value)}) }).NotTo(Panic())
		}
	})
	DescribeTable("ignores canonical unknown keys without narrowing or panicking", func(wire string) {
		body, err := hex.DecodeString(wire)
		Expect(err).NotTo(HaveOccurred())
		req, err := decodeRequest(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(req).To(HaveKey(99))
	}, Entry("minimum negative", "a21863003bffffffffffffffff00"), Entry("negative int64 boundary", "a21863003b7fffffffffffffff00"), Entry("below int64", "a21863003b800000000000000000"), Entry("positive int64 boundary", "a21863001b7fffffffffffffff00"), Entry("positive above int64", "a21863001b800000000000000000"), Entry("positive maximum", "a21863001bffffffffffffffff00"), Entry("nested negative key", "a11863a13bffffffffffffffff00"), Entry("distinct numeric and text keys", "a30100186300613100"))
	It("accepts an independent actual assertion with a minimum negative unknown key", func() {
		// {1:"example.com", 2:h'00' * 32, -18446744073709551616:0}.
		body, err := hex.DecodeString("a3016b6578616d706c652e636f6d02582000000000000000000000000000000000000000000000000000000000000000003bffffffffffffffff00")
		Expect(err).NotTo(HaveOccurred())
		store := &identityStore{stubStore: stubStore{creds: true}}
		a := NewAuthenticator(store, allowGate{}, nil)
		a.writer = &fakeWriter{}
		status, _ := a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(statusOK))
		Expect(store.asserted).To(HaveLen(1))
		// The same unknown key cannot conceal a malformed known hash.
		body, err = hex.DecodeString("a3016b6578616d706c652e636f6d02003bffffffffffffffff00")
		Expect(err).NotTo(HaveOccurred())
		status, _ = a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(statusUnexpectedType))
		Expect(store.asserted).To(HaveLen(1))
	})
	DescribeTable("rejects wire duplicates even when Go pointer keys differ", func(wire string) {
		body, err := hex.DecodeString(wire)
		Expect(err).NotTo(HaveOccurred())
		_, err = decodeRequest(body)
		Expect(err).To(HaveOccurred())
	}, Entry("large negative duplicate", "a23bffffffffffffffff003bffffffffffffffff01"), Entry("integer nonminimal alias", "a20100180100"), Entry("nested large negative duplicate", "a11863a23bffffffffffffffff003bffffffffffffffff01"))
})
