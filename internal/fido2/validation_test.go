//go:build linux

package fido2

import (
	"encoding/base64"

	"github.com/metalgrid/kpxcd/internal/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Step 3 service properties and RP semantics", func() {
	DescribeTable("represents independent established UP/UV verdicts", func(up, uv bool, flags byte) {
		pool, _ := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		entry, err := svc.CreatePasskeyWithUserHandle(firstPoolUUID(pool), "example.com", "", "", "", []byte{0}, nil)
		Expect(err).NotTo(HaveOccurred())
		result, err := svc.SignAssertion(SignAssertionInput{RPID: entry.RPID, CredentialID: entry.CredentialID, ClientDataHash: make([]byte, 32), UserPresent: up, UserVerified: uv})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.AuthenticatorData[32]).To(Equal(flags))
	}, Entry("neither", false, false, byte(0)), Entry("presence", true, false, byte(FlagUP)), Entry("verification", false, true, byte(FlagUV)), Entry("both", true, true, byte(FlagUP|FlagUV)))
	DescribeTable("persists and asserts ordinary credentials without RP-specific probe exceptions", func(rpID string) {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		store := NewCtapStore(svc, pool, path)
		id, handle, cose, err := store.Create(rpID, "RP", "user", "User", []byte{0, 1, 0}, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(handle).To(Equal([]byte{0, 1, 0}))
		reopened := reopenPool(path)
		DeferCleanup(reopened.Close)
		rsvc := NewFido2Service(&config.Fido2Config{Enabled: true}, reopened)
		entry, err := rsvc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(id))
		Expect(err).NotTo(HaveOccurred())
		Expect(entry.PublicKeyCOSE).To(Equal(cose))
		Expect(entry.RPID).To(Equal(rpID))
		rstore := NewCtapStore(rsvc, reopened, path)
		found, err := rstore.HasCredential(rpID, id)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		used, got, auth, sig, err := rstore.Assert(rpID, id, make([]byte, 32), true, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(used).To(Equal(id))
		Expect(got).To(Equal(handle))
		Expect(auth[32]).To(Equal(byte(FlagUP)))
		Expect(sig).NotTo(BeEmpty())
		found, err = rstore.HasCredential("other.example", id)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeFalse())
	}, Entry(".dummy", ".dummy"), Entry("make.me.blink", "make.me.blink"))
})
