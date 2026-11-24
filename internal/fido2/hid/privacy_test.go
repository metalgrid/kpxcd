//go:build linux

package hid

import (
	"bytes"
	"context"
	"errors"
	"log/slog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type privateErrorStore struct{ stubStore }

func (*privateErrorStore) Create(string, string, string, string, []byte, bool) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, errors.New("private-vault-entry-and-credential")
}

func (*privateErrorStore) Assert(string, []byte, []byte, bool, bool) ([]byte, []byte, []byte, []byte, error) {
	return nil, nil, nil, nil, errors.New("private-vault-entry-and-credential")
}

var _ = Describe("Step 6 FIDO request privacy", func() {
	It("logs fixed creation and assertion failures without request or storage account data", func() {
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		a := NewAuthenticator(&privateErrorStore{stubStore{creds: true}}, allowGate{}, logger)
		a.writer = &fakeWriter{}
		DeferCleanup(a.Close)
		registration, err := marshalRequest(map[int]any{
			1: make([]byte, 32),
			2: map[string]any{"id": "private-rp.example", "name": "private-rp-name"},
			3: map[string]any{"id": []byte("private-user-handle"), "name": "private-account-name"},
			4: []any{map[string]any{"type": "public-key", "alg": -7}},
		})
		Expect(err).NotTo(HaveOccurred())
		status, _ := a.makeCredential(context.Background(), registration, 1)
		Expect(status).To(Equal(byte(0x27)))
		assertion, err := marshalRequest(map[int]any{
			1: "private-rp.example", 2: make([]byte, 32),
			3: []any{map[string]any{"type": "public-key", "id": []byte{0xaa, 0xbb}}},
		})
		Expect(err).NotTo(HaveOccurred())
		status, _ = a.getAssertion(context.Background(), assertion, 1)
		Expect(status).To(Equal(byte(0x22)))
		Expect(logs.String()).To(ContainSubstring("hid: credential creation failed"))
		Expect(logs.String()).To(ContainSubstring("hid: assertion refused"))
		Expect(logs.String()).NotTo(ContainSubstring("private-"))
	})
})
