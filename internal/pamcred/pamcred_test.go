//go:build linux

package pamcred

import (
	"encoding/hex"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DerivePAMToken", func() {
	It("derives the legacy token deterministically from the login password", func() {
		got := DerivePAMToken([]byte("login-password"))
		want, err := hex.DecodeString("6746851997ae6dd1b118025baa56753514a2bf21ad02d1f0254bdfbfa9450c74")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(want))
		Expect(got).To(HaveLen(PAMTokenLen))
		Expect(got).NotTo(Equal([]byte("login-password")), "derived token must not equal the raw password")
	})

	It("produces different tokens for different passwords", func() {
		first := DerivePAMToken([]byte("login-password"))
		second := DerivePAMToken([]byte("login-password-2"))
		Expect(first).NotTo(Equal(second))
	})
})

var _ = Describe("DerivePAMTokenV2", func() {
	It("is stable per password and UID and differs from the legacy token", func() {
		first := DerivePAMTokenV2([]byte("login-password"))
		second := DerivePAMTokenV2([]byte("login-password"))
		Expect(first).To(Equal(second), "same password and UID must produce the same V2 token")
		Expect(first).NotTo(Equal(DerivePAMToken([]byte("login-password"))), "V2 token must differ from legacy token")
		Expect(first).To(HaveLen(PAMTokenLen))
	})
})

var _ = Describe("Seal/Open identity", func() {
	It("round-trips an identity and refuses a wrong token", func() {
		token := []byte("login-password")
		identity, err := GenerateIdentity()
		Expect(err).NotTo(HaveOccurred())

		sealed, err := SealIdentity(identity, token)
		Expect(err).NotTo(HaveOccurred())

		opened, err := OpenIdentity(sealed, token)
		Expect(err).NotTo(HaveOccurred())
		Expect(opened.String()).To(Equal(identity.String()))

		_, err = OpenIdentity(sealed, []byte("wrong-password"))
		Expect(err).To(HaveOccurred(), "expected wrong token to fail")
	})
})

var _ = Describe("Seal/Open credential", func() {
	It("round-trips a database credential through the identity", func() {
		identity, err := GenerateIdentity()
		Expect(err).NotTo(HaveOccurred())

		cred, err := NewRandomDBCredential("/tmp/default.kdbx")
		Expect(err).NotTo(HaveOccurred())

		sealed, err := SealCredential(cred, identity.Recipient())
		Expect(err).NotTo(HaveOccurred())

		opened, err := OpenCredential(sealed, identity)
		Expect(err).NotTo(HaveOccurred())
		Expect(opened.DBPath).To(Equal(cred.DBPath))
		Expect(opened.DBPassword).To(Equal(cred.DBPassword))
		Expect(opened.Version).To(Equal(CredentialVersion))
	})
})
