//go:build linux

package hid

import (
	"context"
	"encoding/hex"

	"github.com/fxamacker/cbor/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Ordinary host fixtures use a separately configured canonical encoder. Literal
// wire cases below do not use an encoder, including noncanonical input cases.
func marshalRequest(value any) ([]byte, error) {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(value)
}

type operationGate struct {
	calls        chan Operation
	approved     bool
	presence     bool
	verification bool
}

func (g operationGate) Approve(_ context.Context, op Operation) Approval {
	g.calls <- op
	return Approval{Approved: g.approved, UserPresence: g.presence, UserVerification: g.verification}
}

func validRegistration() map[int]any {
	return map[int]any{1: make([]byte, 32), 2: map[string]any{"id": "example.com"}, 3: map[string]any{"id": []byte{1}}, 4: []any{map[string]any{"alg": -7, "type": "public-key"}}}
}

var _ = Describe("Step 3 command validation", func() {
	DescribeTable("establishes independent assertion properties before signing", func(options map[string]any, approved bool, want byte, flags byte, calls int, up, uv bool) {
		store := &identityStore{stubStore: stubStore{creds: true}}
		gate := operationGate{calls: make(chan Operation, 2), approved: approved, presence: flags&FlagUP != 0, verification: flags&FlagUV != 0}
		a := NewAuthenticator(store, gate, nil)
		a.writer = &fakeWriter{}
		req := map[int]any{1: "example.com", 2: make([]byte, 32)}
		if options != nil {
			req[5] = options
		}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, response := a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(want))
		Expect(len(gate.calls)).To(Equal(calls))
		if calls == 1 {
			Expect(<-gate.calls).To(Equal(Operation{Kind: OperationAuthenticate, RPID: "example.com", UserPresence: up, UserVerification: uv}))
		}
		if want != statusOK {
			Expect(store.asserted).To(BeEmpty())
			Expect(response).To(BeNil())
			return
		}
		Expect(store.asserted).To(HaveLen(1))
		var resp getAssertionResponse
		Expect(cbor.Unmarshal(response, &resp)).To(Succeed())
		Expect(resp.AuthData[32]).To(Equal(flags))
	},
		Entry("defaults", nil, true, statusOK, byte(FlagUP), 1, true, false),
		Entry("false false silent denial irrelevant", map[string]any{"up": false, "uv": false}, false, statusOK, byte(0), 0, false, false),
		Entry("false true", map[string]any{"up": false, "uv": true}, true, statusOK, byte(FlagUV), 1, false, true),
		Entry("true false", map[string]any{"up": true, "uv": false}, true, statusOK, byte(FlagUP), 1, true, false),
		Entry("true true", map[string]any{"up": true, "uv": true}, true, statusOK, byte(FlagUP|FlagUV), 1, true, true),
		Entry("UV without UP denied cannot sign", map[string]any{"up": false, "uv": true}, false, statusOperationDenied, byte(0), 1, false, true),
		Entry("UP denied", map[string]any{"up": true, "uv": false}, false, statusOperationDenied, byte(0), 1, true, false),
		Entry("both denied", map[string]any{"up": true, "uv": true}, false, statusOperationDenied, byte(0), 1, true, true),
		Entry("unknown userPresence ignored", map[string]any{"userPresence": false}, true, statusOK, byte(FlagUP), 1, true, false),
		Entry("unknown option value ignored", map[string]any{"future": []any{1}}, true, statusOK, byte(FlagUP), 1, true, false))

	DescribeTable("validates complete registration before any gate or mutation", func(key int, value any, remove bool, want byte) {
		req := validRegistration()
		if remove {
			delete(req, key)
		} else {
			req[key] = value
		}
		gate := &countedGate{approved: true}
		store := &stubStore{}
		a := NewAuthenticator(store, gate, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, response := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(want))
		Expect(response).To(BeNil())
		Expect(store.createCalls).To(BeZero())
		Expect(gate.calls.Load()).To(BeZero())
	},
		Entry("missing hash", 1, nil, true, statusMissingParam),
		Entry("hash text", 1, "hash", false, statusUnexpectedType),
		Entry("hash short", 1, make([]byte, 31), false, statusInvalidLength),
		Entry("hash long", 1, make([]byte, 33), false, statusInvalidLength),
		Entry("missing RP", 2, nil, true, statusMissingParam),
		Entry("null RP", 2, nil, false, statusUnexpectedType),
		Entry("RP array", 2, []any{}, false, statusUnexpectedType),
		Entry("RP id absent", 2, map[string]any{}, false, statusMissingParam),
		Entry("RP id bytes", 2, map[string]any{"id": []byte{1}}, false, statusUnexpectedType),
		Entry("empty RP", 2, map[string]any{"id": ""}, false, statusInvalidParameter),
		Entry("RP name wrong", 2, map[string]any{"id": "example.com", "name": 1}, false, statusUnexpectedType),
		Entry("RP icon wrong", 2, map[string]any{"id": "example.com", "icon": false}, false, statusUnexpectedType),
		Entry("missing user", 3, nil, true, statusMissingParam),
		Entry("user text", 3, "user", false, statusUnexpectedType),
		Entry("bad optional display name", 3, map[string]any{"id": []byte{1}, "displayName": 1}, false, statusUnexpectedType),
		Entry("bad optional username", 3, map[string]any{"id": []byte{1}, "name": false}, false, statusUnexpectedType),
		Entry("missing algorithms", 4, nil, true, statusMissingParam),
		Entry("algorithms not array", 4, map[string]any{}, false, statusUnexpectedType),
		Entry("algorithm item not map", 4, []any{1}, false, statusUnexpectedType),
		Entry("algorithm missing", 4, []any{map[string]any{"type": "public-key"}}, false, statusMissingParam),
		Entry("type missing", 4, []any{map[string]any{"alg": -7}}, false, statusMissingParam),
		Entry("algorithm float", 4, []any{map[string]any{"type": "public-key", "alg": -7.0}}, false, statusUnexpectedType),
		Entry("valid algorithm before malformed", 4, []any{map[string]any{"type": "public-key", "alg": -7}, map[string]any{"type": "public-key", "alg": "-7"}}, false, statusUnexpectedType),
		Entry("no supported algorithms", 4, []any{}, false, statusUnsupportedAlgorithm),
		Entry("bad exclude list", 5, []any{map[string]any{"type": "public-key", "id": []byte{1}, "transports": []any{1}}}, false, statusUnexpectedType),
		Entry("bad extensions", 6, []any{}, false, statusUnexpectedType),
		Entry("bad options", 7, true, false, statusUnexpectedType),
		Entry("uv not bool", 7, map[string]any{"uv": 1}, false, statusUnexpectedType),
		Entry("rk not bool", 7, map[string]any{"rk": "true"}, false, statusUnexpectedType),
		Entry("up not bool", 7, map[string]any{"up": nil}, false, statusUnexpectedType),
		Entry("up true forbidden", 7, map[string]any{"up": true}, false, statusInvalidOption),
		Entry("up false forbidden", 7, map[string]any{"up": false}, false, statusInvalidOption),
		Entry("bad pinAuth type", 8, "pin", false, statusUnexpectedType),
		Entry("negative protocol", 9, -1, false, statusUnexpectedType))

	DescribeTable("validates assertion before any gate or signature", func(key int, value any, remove bool, want byte) {
		req := map[int]any{1: "example.com", 2: make([]byte, 32)}
		if remove {
			delete(req, key)
		} else {
			req[key] = value
		}
		gate := &countedGate{approved: true}
		store := &identityStore{stubStore: stubStore{creds: true}}
		a := NewAuthenticator(store, gate, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, response := a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(want))
		Expect(response).To(BeNil())
		Expect(store.asserted).To(BeEmpty())
		Expect(gate.calls.Load()).To(BeZero())
	}, Entry("missing RP", 1, nil, true, statusMissingParam),
		Entry("RP type", 1, 1, false, statusUnexpectedType),
		Entry("missing hash", 2, nil, true, statusMissingParam),
		Entry("hash null", 2, nil, false, statusUnexpectedType),
		Entry("hash short", 2, []byte{1}, false, statusInvalidLength),
		Entry("hash long", 2, make([]byte, 33), false, statusInvalidLength),
		Entry("extensions type", 4, 1, false, statusUnexpectedType),
		Entry("options type", 5, []any{}, false, statusUnexpectedType),
		Entry("up type", 5, map[string]any{"up": "false"}, false, statusUnexpectedType),
		Entry("uv type", 5, map[string]any{"uv": 1}, false, statusUnexpectedType),
		Entry("rk forbidden true", 5, map[string]any{"rk": true}, false, statusInvalidOption),
		Entry("rk forbidden false", 5, map[string]any{"rk": false}, false, statusInvalidOption),
		Entry("pin type", 6, true, false, statusUnexpectedType),
		Entry("protocol type", 7, "1", false, statusUnexpectedType))

	DescribeTable("refuses unsupported authentication without downgrade", func(auth any, hasAuth bool, protocol any, hasProtocol bool, want byte, calls int) {
		for _, command := range []byte{cmdMakeCredential, cmdGetAssertion} {
			req := validRegistration()
			authKey, protocolKey := 8, 9
			if command == cmdGetAssertion {
				req = map[int]any{1: "example.com", 2: make([]byte, 32), 5: map[string]any{"up": false, "uv": true}}
				authKey, protocolKey = 6, 7
			}
			if hasAuth {
				req[authKey] = auth
			}
			if hasProtocol {
				req[protocolKey] = protocol
			}
			gate := &countedGate{approved: true}
			store := &identityStore{stubStore: stubStore{creds: true}}
			a := NewAuthenticator(store, gate, nil)
			a.writer = &fakeWriter{}
			body, err := marshalRequest(req)
			Expect(err).NotTo(HaveOccurred())
			status, response := a.runCommand(context.Background(), command, body, 1)
			Expect(status).To(Equal(want))
			Expect(response).To(BeNil())
			Expect(gate.calls.Load()).To(Equal(int32(calls)))
			Expect(store.createCalls).To(BeZero())
			Expect(store.asserted).To(BeEmpty())
		}
	}, Entry("auth without protocol", make([]byte, 16), true, nil, false, statusMissingParam, 0),
		Entry("protocol without auth", nil, false, 1, true, statusMissingParam, 0),
		Entry("unsupported protocol", make([]byte, 16), true, 2, true, statusPINAuthInvalid, 0),
		Entry("unverifiable token", make([]byte, 16), true, 1, true, statusPINAuthInvalid, 0),
		Entry("short authentication", []byte{1}, true, 1, true, statusInvalidLength, 0),
		Entry("long authentication", make([]byte, 17), true, 1, true, statusInvalidLength, 0),
		Entry("empty authentication touch probe", []byte{}, true, 1, true, statusPINNotSet, 1),
		Entry("empty probe without protocol", []byte{}, true, nil, false, statusPINNotSet, 1),
		Entry("empty probe with unknown protocol", []byte{}, true, 99, true, statusPINNotSet, 1))

	DescribeTable("protects no-credential disclosure with the requested consent", func(options map[string]any, approved bool, want byte, calls int) {
		gate := &countedGate{approved: approved}
		a := NewAuthenticator(&stubStore{}, gate, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(map[int]any{1: "example.com", 2: make([]byte, 32), 5: options})
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(want))
		Expect(gate.calls.Load()).To(Equal(int32(calls)))
	}, Entry("default UP approval", map[string]any{}, true, statusNoCredentials, 1),
		Entry("default UP denial", map[string]any{}, false, statusOperationDenied, 1),
		Entry("silent", map[string]any{"up": false}, false, statusNoCredentials, 0),
		Entry("UV only denial", map[string]any{"up": false, "uv": true}, false, statusOperationDenied, 1))

	It("keeps exclusion consent ahead of unsupported algorithms and invalid command options", func() {
		req := validRegistration()
		req[4] = []any{map[string]any{"type": "public-key", "alg": -8}}
		req[7] = map[string]any{"up": true}
		req[5] = []any{map[string]any{"type": "public-key", "id": []byte{1}}}
		gate := &countedGate{approved: true}
		store := &stubStore{excluded: true}
		a := NewAuthenticator(store, gate, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(statusCredentialExcluded))
		Expect(gate.calls.Load()).To(Equal(int32(1)))
		Expect(store.createCalls).To(BeZero())
	})
	It("denies an empty PIN touch probe without disclosing PIN state", func() {
		for _, command := range []byte{cmdMakeCredential, cmdGetAssertion} {
			req := validRegistration()
			if command == cmdMakeCredential {
				req[8] = []byte{}
				req[9] = 1
			} else {
				req = map[int]any{1: "example.com", 2: make([]byte, 32), 6: []byte{}, 7: 1}
			}
			gate := &countedGate{}
			store := &identityStore{stubStore: stubStore{creds: true}}
			a := NewAuthenticator(store, gate, nil)
			a.writer = &fakeWriter{}
			body, err := marshalRequest(req)
			Expect(err).NotTo(HaveOccurred())
			status, _ := a.runCommand(context.Background(), command, body, 1)
			Expect(status).To(Equal(statusOperationDenied))
			Expect(gate.calls.Load()).To(Equal(int32(1)))
			Expect(store.createCalls).To(BeZero())
			Expect(store.asserted).To(BeEmpty())
		}
	})
	It("ignores unknown fields and unsupported extensions without advertising or executing them", func() {
		req := validRegistration()
		req[42] = true
		req[6] = map[string]any{"hmac-secret": true}
		req[7] = map[string]any{"future": 1, "rk": false}
		a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, response := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(statusOK))
		var resp makeCredentialResponse
		Expect(cbor.Unmarshal(response, &resp)).To(Succeed())
		Expect(resp.AuthData[32]).To(Equal(byte(FlagUP | FlagUV | FlagAT)))
		Expect(resp.Fmt).To(Equal("none"))
		Expect(resp.AttStmt).To(BeEmpty())
	})
	It("enforces GetInfo's no-argument length and leaves Reset unsupported", func() {
		a := NewAuthenticator(&stubStore{}, denyGate{}, nil)
		for _, data := range [][]byte{{0xa0}, {0xf6}, {0}} {
			status, response := a.runCommand(context.Background(), cmdGetInfo, data, 1)
			Expect(status).To(Equal(statusInvalidLength))
			Expect(response).To(BeNil())
		}
		status, response := a.runCommand(context.Background(), cmdGetInfo, nil, 1)
		Expect(status).To(Equal(statusOK))
		Expect(response).NotTo(BeEmpty())
		status, response = a.runCommand(context.Background(), 0x07, nil, 1)
		Expect(status).To(Equal(statusInvalidCommand))
		Expect(response).To(BeNil())
		status, _ = a.runCommand(context.Background(), cmdMakeCredential, make([]byte, maxMessageLen), 1)
		Expect(status).To(Equal(statusRequestTooLarge))
	})
})

var _ = Describe("Step 3 approval and response details", func() {
	DescribeTable("checks exactly the registration properties before returning exact flags", func(uv, approved bool) {
		req := validRegistration()
		req[7] = map[string]any{"uv": uv, "rk": true}
		gate := operationGate{calls: make(chan Operation, 1), approved: approved, presence: true, verification: uv}
		store := &stubStore{}
		a := NewAuthenticator(store, gate, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, response := a.makeCredential(context.Background(), body, 1)
		Expect(len(gate.calls)).To(Equal(1))
		Expect(<-gate.calls).To(Equal(Operation{Kind: OperationRegister, RPID: "example.com", UserPresence: true, UserVerification: uv}))
		if !approved {
			Expect(status).To(Equal(statusOperationDenied))
			Expect(store.createCalls).To(BeZero())
			Expect(response).To(BeNil())
			return
		}
		Expect(status).To(Equal(statusOK))
		Expect(store.createCalls).To(Equal(1))
		var resp makeCredentialResponse
		Expect(cbor.Unmarshal(response, &resp)).To(Succeed())
		flags := byte(FlagUP | FlagAT)
		if uv {
			flags |= FlagUV
		}
		Expect(resp.AuthData[32]).To(Equal(flags))
	}, Entry("UP approval", false, true),
		Entry("UP denial", false, false),
		Entry("UP+UV approval", true, true),
		Entry("UP+UV denial", true, false))
	It("advertises only implemented capabilities in canonical response maps", func() {
		a := NewAuthenticator(&stubStore{}, denyGate{}, nil)
		status, body := a.getInfo()
		Expect(status).To(Equal(statusOK))
		var info map[int]any
		Expect(cbor.Unmarshal(body, &info)).To(Succeed())
		Expect(info[1]).To(Equal([]any{"FIDO_2_0"}))
		Expect(info[2]).To(BeEmpty())
		Expect(info[3]).To(HaveLen(16))
		Expect(info[4]).To(Equal(map[any]any{"rk": true, "up": true, "uv": true}))
		Expect(info).NotTo(HaveKey(6))
		Expect(info).To(HaveLen(6))
		Expect(info[10]).To(Equal([]any{map[any]any{"alg": int64(-7), "type": "public-key"}}))
		canonical, err := marshalRequest(info)
		Expect(err).NotTo(HaveOccurred())
		Expect(body).To(Equal(canonical))
	})
	It("ignores unknown entity fields instead of treating them as recognized fields", func() {
		req := validRegistration()
		req[2].(map[string]any)["displayName"] = false
		req[3].(map[string]any)["future"] = 1
		a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
		a.writer = &fakeWriter{}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(statusOK))
	})
})

var _ = Describe("Step 3 CTAP CBOR wire policy", func() {
	DescribeTable("refuses malformed or noncanonical raw CBOR without panicking", func(wire string, want byte) {
		data, err := hex.DecodeString(wire)
		Expect(err).NotTo(HaveOccurred())
		a := NewAuthenticator(&stubStore{}, denyGate{}, nil)
		for _, command := range []byte{cmdMakeCredential, cmdGetAssertion} {
			status, response := a.runCommand(context.Background(), command, data, 1)
			Expect(status).To(Equal(want))
			Expect(response).To(BeNil())
		}
	}, Entry("null top level", "f6", statusUnexpectedType),
		Entry("integer top level", "01", statusUnexpectedType),
		Entry("array top level", "80", statusUnexpectedType),
		Entry("byte-string top level", "40", statusUnexpectedType),
		Entry("text top level", "60", statusUnexpectedType),
		Entry("duplicate keys", "a201010102", statusInvalidCBOR),
		Entry("nested duplicate keys", "a11863a201010102", statusInvalidCBOR),
		Entry("noncomparable array key", "a18001", statusInvalidCBOR),
		Entry("noncomparable map key", "a1a001", statusInvalidCBOR),
		Entry("tag", "d864a0", statusInvalidCBOR),
		Entry("nested tag", "a11863c001", statusInvalidCBOR),
		Entry("indefinite map", "bfff", statusInvalidCBOR),
		Entry("indefinite bytes", "a118635fff", statusInvalidCBOR),
		Entry("indefinite array", "a118639fff", statusInvalidCBOR),
		Entry("empty body", "", statusInvalidCBOR),
		Entry("nonminimal integer", "a1180101", statusInvalidCBOR),
		Entry("nonminimal uint16", "a119006301", statusInvalidCBOR),
		Entry("nonminimal uint32", "a11a0000006301", statusInvalidCBOR),
		Entry("nonminimal uint64", "a11b000000000000006301", statusInvalidCBOR),
		Entry("nonminimal string length", "a11863780161", statusInvalidCBOR),
		Entry("nonminimal map length", "b800", statusInvalidCBOR),
		Entry("unordered keys", "a202010101", statusInvalidCBOR),
		Entry("nested unordered keys", "a11863a202010101", statusInvalidCBOR),
		Entry("trailing object", "a000", statusInvalidCBOR),
		Entry("truncated map", "a101", statusInvalidCBOR),
		Entry("invalid UTF8", "a1186361ff", statusInvalidCBOR),
		Entry("five nesting levels", "a1186381818180", statusInvalidCBOR))
	DescribeTable("accepts canonical unknown values at four nesting levels and preserves float representations", func(wire string) {
		data, err := hex.DecodeString(wire)
		Expect(err).NotTo(HaveOccurred())
		req, err := decodeRequest(data)
		Expect(err).NotTo(HaveOccurred())
		Expect(req).To(HaveKey(99))
	}, Entry("four levels", "a11863818180"),
		Entry("float16", "a11863f93c00"),
		Entry("NaN bit representation", "a11863f97e01"),
		Entry("float32", "a11863fa3f800000"),
		Entry("float64", "a11863fb3ff0000000000000"),
		Entry("byte-string unknown key", "a2186300410100"),
		Entry("large unsigned unknown key", "a21863001bffffffffffffffff01"))
})
