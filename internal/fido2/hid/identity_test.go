//go:build linux

package hid

import (
	"context"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type identityStore struct {
	stubStore
	handle   []byte
	asserted [][]byte
}

func (s *identityStore) Create(rpID, rpName, userName, userDisplayName string, userID []byte, resident bool) ([]byte, []byte, []byte, error) {
	s.handle = append([]byte(nil), userID...)
	return s.stubStore.Create(rpID, rpName, userName, userDisplayName, userID, resident)
}
func (s *identityStore) Assert(rpID string, id, hash []byte, up, uv bool) ([]byte, []byte, []byte, []byte, error) {
	s.asserted = append(s.asserted, id)
	return s.stubStore.Assert(rpID, id, hash, up, uv)
}

func (s *identityStore) AssertResident(ref CredentialReference, original []CredentialReference, hash []byte, up, uv bool) (ResidentAssertion, error) {
	return stubResidentAssertion(s, ref, hash, up, uv)
}

var _ = Describe("Step 2 command identity", func() {
	DescribeTable("enforces supplied allow-list restrictions before signing", func(list any, include bool, want byte) {
		store := &identityStore{stubStore: stubStore{creds: true}}
		a := NewAuthenticator(store, allowGate{}, nil)
		a.writer = &fakeWriter{}
		req := map[int]any{1: "example.com", 2: make([]byte, 32)}
		if include {
			req[3] = list
		}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.getAssertion(context.Background(), body, 1)
		Expect(status).To(Equal(want))
		if want == statusOK {
			Expect(store.asserted).To(HaveLen(1))
			if items, ok := list.([]any); ok && len(items) > 0 {
				Expect(store.asserted[0]).To(Equal([]byte{0xaa, 0xbb}))
			}
		} else {
			Expect(store.asserted).To(BeEmpty())
		}
	},
		Entry("absent resident", nil, false, statusOK),
		Entry("empty resident", []any{}, true, statusOK),
		Entry("not an array", "bad", true, byte(0x11)),
		Entry("null", nil, true, byte(0x11)),
		Entry("not a descriptor", []any{1}, true, byte(0x11)),
		Entry("missing type", []any{map[string]any{"id": []byte{0xaa, 0xbb}}}, true, statusMissingParam),
		Entry("wrong id type", []any{map[string]any{"type": "public-key", "id": "bad"}}, true, byte(0x11)),
		Entry("empty id", []any{map[string]any{"type": "public-key", "id": []byte{}}}, true, byte(0x03)),
		Entry("unknown type is not a key", []any{map[string]any{"type": "future-key", "id": []byte{0xaa, 0xbb}}}, true, statusNoCredentials),
		Entry("unknown before supported match", []any{map[string]any{"type": "future-key", "id": []byte{0xaa, 0xbb}}, map[string]any{"type": "public-key", "id": []byte{0xaa, 0xbb}}}, true, statusOK),
		Entry("no match", []any{map[string]any{"type": "public-key", "id": []byte{1}}}, true, statusNoCredentials),
		Entry("later match", []any{map[string]any{"type": "public-key", "id": []byte{1}}, map[string]any{"type": "public-key", "id": []byte{0xaa, 0xbb}}}, true, statusOK),
		Entry("valid then malformed cannot downgrade", []any{map[string]any{"type": "public-key", "id": []byte{0xaa, 0xbb}}, map[string]any{"id": []byte{1}}}, true, statusMissingParam))

	DescribeTable("validates browser user identity before creation", func(user map[string]any, want byte) {
		store := &identityStore{}
		a := NewAuthenticator(store, allowGate{}, nil)
		a.writer = &fakeWriter{}
		req := map[int]any{1: make([]byte, 32), 2: map[string]any{"id": "example.com"}, 3: user, 4: []any{map[string]any{"type": "public-key", "alg": -7}}}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(want))
		if want == statusOK {
			Expect(store.handle).To(Equal(user["id"]))
			Expect(store.createCalls).To(Equal(1))
		} else {
			Expect(store.createCalls).To(BeZero())
		}
	}, Entry("missing", map[string]any{}, statusMissingParam), Entry("text", map[string]any{"id": "abc"}, byte(0x11)), Entry("empty", map[string]any{"id": []byte{}}, byte(0x03)), Entry("65 bytes", map[string]any{"id": make([]byte, 65)}, byte(0x03)), Entry("64 zero bytes", map[string]any{"id": make([]byte, 64)}, statusOK))

	It("does not exclude an unknown credential type", func() {
		store := &stubStore{excluded: true}
		a := NewAuthenticator(store, allowGate{}, nil)
		a.writer = &fakeWriter{}
		req := map[int]any{1: make([]byte, 32), 2: map[string]any{"id": "example.com"}, 3: map[string]any{"id": []byte{0}}, 4: []any{map[string]any{"type": "public-key", "alg": -7}}, 5: []any{map[string]any{"type": "future-key", "id": []byte{0xaa, 0xbb}}}}
		body, err := marshalRequest(req)
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.makeCredential(context.Background(), body, 1)
		Expect(status).To(Equal(statusOK))
		Expect(store.createCalls).To(Equal(1))
	})
})
