//go:build linux

package fido2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Step 6 legacy configuration runtime isolation", func() {
	DescribeTable("does not change explicit creation or actual verification verdicts", func(preference string, up, uv bool) {
		pool, _ := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		path := filepath.Join(GinkgoT().TempDir(), "legacy.toml")
		Expect(os.WriteFile(path, []byte(fmt.Sprintf("[fido2]\nenabled = true\naaguid = \"another-vendor\"\nalgorithms = [-25]\nuser_verification = %q\n", preference)), 0o600)).To(Succeed())
		cfg, err := config.Load(path)
		Expect(err).NotTo(HaveOccurred())
		svc := NewFido2Service(&cfg.Fido2, pool)
		for _, algorithm := range []int{-7, -8} {
			pk, err := svc.CreatePasskey(firstPoolUUID(pool), "example.com", "", "", "", []int{algorithm})
			Expect(err).NotTo(HaveOccurred(), "legacy algorithms must not change explicit local API generation")
			result, err := svc.SignAssertion(SignAssertionInput{RPID: "example.com", CredentialID: pk.CredentialID, ClientDataHash: make([]byte, 32), UserPresent: up, UserVerified: uv})
			Expect(err).NotTo(HaveOccurred())
			flags := byte(0)
			if up {
				flags |= 1
			}
			if uv {
				flags |= 4
			}
			Expect(result.AuthenticatorData[32]).To(Equal(flags))
		}
	}, Entry("discouraged cannot erase established UV", "discouraged", false, true), Entry("required cannot manufacture UV", "required", true, false), Entry("unknown does not invent checks", "unknown", false, false))
})

var _ = Describe("Step 2 credential identity", func() {
	DescribeTable("round-trips exact browser handles through CtapStore, disk and assertion", func(handle []byte) {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		store := NewCtapStore(svc, pool, path)
		id, got, _, err := store.Create("example.com", "Example", "alice", "Alice", handle, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(handle))
		original, err := svc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(id))
		Expect(err).NotTo(HaveOccurred())
		reopened := reopenPool(path)
		DeferCleanup(reopened.Close)
		rsvc := NewFido2Service(&config.Fido2Config{Enabled: true}, reopened)
		saved, err := rsvc.FindPasskeyByCredentialID(original.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.UserHandle).To(Equal(base64.RawURLEncoding.EncodeToString(handle)))
		Expect(saved.PrivateKeyPEM).To(Equal(original.PrivateKeyPEM))
		Expect(saved.PublicKeyCOSE).To(Equal(original.PublicKeyCOSE))
		used, asserted, _, sig, err := NewCtapStore(rsvc, reopened, path).Assert("example.com", id, make([]byte, 32), true, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(used).To(Equal(id))
		Expect(asserted).To(Equal(handle))
		Expect(sig).NotTo(BeEmpty())
	}, Entry("one zero byte", []byte{0}), Entry("embedded zeros", []byte{0, 1, 0, 255, 0}), Entry("64 bytes", bytes.Repeat([]byte{0}, 64)))

	DescribeTable("refuses invalid browser handles without writing entries", func(handle []byte) {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		_, _, _, err = NewCtapStore(svc, pool, path).Create("example.com", "Example", "user", "User", handle, false)
		Expect(err).To(MatchError(ContainSubstring("1..64 bytes")))
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
		found, err := svc.FindPasskeysByRPID("", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeEmpty())
	}, Entry("absent", []byte(nil)), Entry("empty", []byte{}), Entry("65 bytes", make([]byte, 65)))

	It("binds actual-store lookup to RP and ID without advancing counters", func() {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		store := NewCtapStore(svc, pool, path)
		id, _, _, err := store.Create("example.com", "", "", "", []byte{0}, false)
		Expect(err).NotTo(HaveOccurred())
		for _, rp := range []string{"other.example", "example.com"} {
			match, err := store.HasCredential(rp, id)
			Expect(err).NotTo(HaveOccurred())
			Expect(match).To(Equal(rp == "example.com"))
		}
		_, _, _, sig, err := store.Assert("other.example", id, make([]byte, 32), true, false)
		Expect(err).To(HaveOccurred())
		Expect(sig).To(BeNil())
		saved, err := svc.FindPasskeyByCredentialID(base64.RawURLEncoding.EncodeToString(id))
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.SignCount).To(BeZero())
	})

	It("uses an imported credential without changing its key, ID or handle", func() {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		_, key, err := generateKeyPair(COSEAlgES256)
		Expect(err).NotTo(HaveOccurred())
		input := ImportPasskeyInput{RPID: "example.com", CredentialID: base64.RawURLEncoding.EncodeToString([]byte{0, 9, 0}), UserHandle: base64.RawURLEncoding.EncodeToString([]byte{0, 8, 0}), PrivateKeyPEM: key, SignCount: 41}
		_, err = svc.ImportPasskey(firstPoolUUID(pool), input)
		Expect(err).NotTo(HaveOccurred())
		reopened := reopenPool(path)
		DeferCleanup(reopened.Close)
		rsvc := NewFido2Service(&config.Fido2Config{Enabled: true}, reopened)
		saved, err := rsvc.FindPasskeyByCredentialID(input.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.SignCount).To(Equal(input.SignCount))
		result, err := rsvc.SignAssertion(SignAssertionInput{RPID: input.RPID, CredentialID: input.CredentialID, ClientDataHash: make([]byte, 32), UserPresent: true})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.CredentialID).To(Equal([]byte{0, 9, 0}))
		Expect(result.UserHandle).To(Equal([]byte{0, 8, 0}))
		Expect(result.SignCount).To(Equal(uint32(42)))
		saved, err = rsvc.FindPasskeyByCredentialID(input.CredentialID)
		Expect(err).NotTo(HaveOccurred())
		Expect(saved.PrivateKeyPEM).To(Equal(key))
		Expect(saved.UserHandle).To(Equal(input.UserHandle))
	})

	It("preserves imported keys, IDs, handles and exhausted counters on disk", func() {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		_, key, err := generateKeyPair(COSEAlgES256)
		Expect(err).NotTo(HaveOccurred())
		input := ImportPasskeyInput{RPID: "example.com", CredentialID: base64.RawURLEncoding.EncodeToString([]byte{0, 9, 0}), UserHandle: base64.RawURLEncoding.EncodeToString([]byte{0, 8, 0}), PrivateKeyPEM: key, SignCount: ^uint32(0)}
		_, err = svc.ImportPasskey(firstPoolUUID(pool), input)
		Expect(err).NotTo(HaveOccurred())
		before, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		for range 2 {
			reopened := reopenPool(path)
			DeferCleanup(reopened.Close)
			rsvc := NewFido2Service(&config.Fido2Config{Enabled: true}, reopened)
			result, err := rsvc.SignAssertion(SignAssertionInput{RPID: input.RPID, CredentialID: input.CredentialID, ClientDataHash: make([]byte, 32), UserPresent: true})
			Expect(err).To(MatchError(ContainSubstring("counter exhausted")))
			Expect(result).To(BeNil())
			saved, err := rsvc.FindPasskeyByCredentialID(input.CredentialID)
			Expect(err).NotTo(HaveOccurred())
			Expect(saved.UserHandle).To(Equal(input.UserHandle))
			Expect(saved.PrivateKeyPEM).To(Equal(key))
			Expect(saved.SignCount).To(Equal(input.SignCount))
		}
		after, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	})

	It("rolls back counter and creation mutations when the atomic save fails", func() {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		local, err := svc.CreatePasskey(firstPoolUUID(pool), "example.com", "", "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		odb, err := pool.Get(firstPoolUUID(pool))
		Expect(err).NotTo(HaveOccurred())
		file, err := os.Open(path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(file.Close)
		// The descriptor aliases the same valid file, so fingerprint checks pass.
		// /proc cannot hold the sibling temporary file required by atomic save.
		odb.Path = fmt.Sprintf("/proc/self/fd/%d", file.Fd())
		result, err := svc.SignAssertion(SignAssertionInput{RPID: "example.com", CredentialID: local.CredentialID, ClientDataHash: make([]byte, 32), UserPresent: true})
		Expect(err).To(MatchError(ContainSubstring("create temp file")))
		Expect(result).To(BeNil())
		created, err := svc.CreatePasskeyWithUserHandle(odb.UUID, "example.com", "", "", "", []byte{1}, nil)
		Expect(err).To(MatchError(ContainSubstring("create temp file")))
		Expect(created).To(BeNil())
		reopened := reopenPool(path)
		DeferCleanup(reopened.Close)
		for _, p := range []*dbpool.DatabasePool{pool, reopened} {
			found, err := NewFido2Service(&config.Fido2Config{Enabled: true}, p).FindPasskeysByRPID("", "")
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(HaveLen(1))
			Expect(found[0].SignCount).To(BeZero())
			Expect(found[0].CredentialID).To(Equal(local.CredentialID))
			Expect(found[0].UserHandle).To(Equal(local.UserHandle))
			Expect(found[0].PrivateKeyPEM).To(Equal(local.PrivateKeyPEM))
		}
	})

	It("returns no signature or new entry when persistence is refused", func() {
		pool, path := newTestPoolWithDB()
		DeferCleanup(pool.Close)
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		local, err := svc.CreatePasskey(firstPoolUUID(pool), "example.com", "", "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		odb, err := pool.Get(firstPoolUUID(pool))
		Expect(err).NotTo(HaveOccurred())
		// Force the optimistic save-conflict path without changing the valid database file.
		odb.Fingerprint = dbpool.FileFingerprint{}
		result, err := svc.SignAssertion(SignAssertionInput{RPID: "example.com", CredentialID: local.CredentialID, ClientDataHash: make([]byte, 32), UserPresent: true})
		Expect(err).To(MatchError(ContainSubstring("changed on disk")))
		Expect(result).To(BeNil())
		created, err := svc.CreatePasskeyWithUserHandle(odb.UUID, "example.com", "", "", "", []byte{1}, nil)
		Expect(err).To(HaveOccurred())
		Expect(created).To(BeNil())
		reopened := reopenPool(path)
		DeferCleanup(reopened.Close)
		for _, p := range []*dbpool.DatabasePool{pool, reopened} {
			found, err := NewFido2Service(&config.Fido2Config{Enabled: true}, p).FindPasskeysByRPID("", "")
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(HaveLen(1))
			Expect(found[0].SignCount).To(BeZero())
			Expect(found[0].UserHandle).To(Equal(local.UserHandle))
		}
	})
})
