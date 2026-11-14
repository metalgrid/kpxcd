//go:build linux

package fido2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/config"
	"github.com/metalgrid/kpxcd/internal/dbpool"
	"github.com/metalgrid/kpxcd/internal/security"
)

// newTestPoolWithDB creates a DatabasePool with a test KDBX database
// and returns it. The database lives in a spec-scoped temp dir; the pool
// is populated with one open database.
func newTestPoolWithDB() (*dbpool.DatabasePool, string) {
	path := filepath.Join(GinkgoT().TempDir(), "test.kdbx")

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("testpassword")

	now := time.Now()
	db.Content.Root.Groups[0].Times = gokeepasslib.TimeData{
		CreationTime:         &wrappers.TimeWrapper{Time: now},
		LastModificationTime: &wrappers.TimeWrapper{Time: now},
	}

	Expect(db.LockProtectedEntries()).To(Succeed())

	f, err := os.Create(path)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	Expect(gokeepasslib.NewEncoder(f).Encode(db)).To(Succeed())

	ss, err := security.NewSecureString("testpassword")
	Expect(err).NotTo(HaveOccurred())
	defer ss.Destroy()

	pool := dbpool.NewDatabasePool(nil)
	_, err = pool.Open(path, dbpool.PasswordCredential(ss))
	Expect(err).NotTo(HaveOccurred())

	return pool, path
}

// reopenPool opens the database file afresh in a new pool.
func reopenPool(path string) *dbpool.DatabasePool {
	ss, err := security.NewSecureString("testpassword")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(ss.Destroy)
	pool := dbpool.NewDatabasePool(nil)
	_, err = pool.Open(path, dbpool.PasswordCredential(ss))
	Expect(err).NotTo(HaveOccurred())
	return pool
}

// firstPoolUUID returns the UUID of the first database in the pool.
func firstPoolUUID(pool *dbpool.DatabasePool) string {
	dbs := pool.List()
	Expect(dbs).NotTo(BeEmpty())
	return dbs[0].UUID
}

var _ = Describe("generateCredentialID", func() {
	It("produces unique base64url values of 32 bytes", func() {
		const iterations = 100
		seen := make(map[string]bool)

		for i := 0; i < iterations; i++ {
			id, err := generateCredentialID()
			Expect(err).NotTo(HaveOccurred())
			Expect(seen).NotTo(HaveKey(id), "duplicate credential ID generated")
			seen[id] = true

			decoded, err := base64.RawURLEncoding.DecodeString(id)
			Expect(err).NotTo(HaveOccurred(), "credential ID is not valid base64url")
			Expect(decoded).To(HaveLen(IDBytes))
		}
	})
})

var _ = Describe("generateUserHandle", func() {
	It("produces unique base64url values of 8 bytes", func() {
		const iterations = 100
		seen := make(map[string]bool)

		for i := 0; i < iterations; i++ {
			handle, err := generateUserHandle()
			Expect(err).NotTo(HaveOccurred())
			Expect(seen).NotTo(HaveKey(handle), "duplicate user handle generated")
			seen[handle] = true

			decoded, err := base64.RawURLEncoding.DecodeString(handle)
			Expect(err).NotTo(HaveOccurred(), "user handle is not valid base64url")
			Expect(decoded).To(HaveLen(8))
		}
	})
})

var _ = Describe("buildAuthenticatorData", func() {
	It("packs rpID hash, flags, and sign count", func() {
		rpID := "example.com"
		flags := byte(FlagUP | FlagUV)
		signCount := uint32(42)

		data := buildAuthenticatorData(rpID, flags, signCount, nil)

		// Structure: rpIDHash (32) + flags (1) + signCount (4).
		Expect(data).To(HaveLen(37))
		expectedHash := sha256.Sum256([]byte(rpID))
		Expect(data[:32]).To(Equal(expectedHash[:]))
		Expect(data[32]).To(Equal(flags))
		gotSignCount := uint32(data[33])<<24 | uint32(data[34])<<16 | uint32(data[35])<<8 | uint32(data[36])
		Expect(gotSignCount).To(Equal(signCount))
	})

	It("appends extension data after the fixed fields", func() {
		extensions := []byte{0xa1, 0x00} // minimal CBOR map
		data := buildAuthenticatorData("test.example.com", byte(FlagUP|FlagED), 0, extensions)

		Expect(data).To(HaveLen(37 + len(extensions)))
		Expect(data[37:]).To(Equal(extensions))
	})
})

var _ = Describe("CreatePasskey", func() {
	It("creates an ES256 key with a valid EC2 COSE public key", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)

		entry, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"github.com", "GitHub", "testuser", "Test User",
			[]int{COSEAlgES256},
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(entry).NotTo(BeNil())

		Expect(entry.RPID).To(Equal("github.com"))
		Expect(entry.RPName).To(Equal("GitHub"))
		Expect(entry.Username).To(Equal("testuser"))
		Expect(entry.CredentialID).NotTo(BeEmpty())
		Expect(entry.UserHandle).NotTo(BeEmpty())
		Expect(entry.PublicKeyCOSE).NotTo(BeEmpty())
		Expect(entry.PrivateKeyPEM).To(HavePrefix("-----BEGIN PRIVATE KEY-----"), "ES256 private key should be PKCS#8")

		var coseKey coseEC2Key
		Expect(cbor.Unmarshal(entry.PublicKeyCOSE, &coseKey)).To(Succeed())
		Expect(coseKey.Kty).To(Equal(2), "want EC2")
		Expect(coseKey.Crv).To(Equal(1), "want P-256")
		Expect(coseKey.Alg).To(Equal(COSEAlgES256))
		Expect(coseKey.X).NotTo(BeEmpty())
		Expect(coseKey.Y).NotTo(BeEmpty())
	})

	It("creates an EdDSA key with a valid OKP COSE public key", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)

		entry, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"gitlab.com", "GitLab", "devuser", "Dev User",
			[]int{COSEAlgEdDSA},
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(entry).NotTo(BeNil())

		Expect(entry.RPID).To(Equal("gitlab.com"))
		Expect(entry.CredentialID).NotTo(BeEmpty())
		Expect(entry.PrivateKeyPEM).To(HavePrefix("-----BEGIN PRIVATE KEY-----"), "EdDSA private key should be PKCS8")

		var coseKey coseOKPKey
		Expect(cbor.Unmarshal(entry.PublicKeyCOSE, &coseKey)).To(Succeed())
		Expect(coseKey.Kty).To(Equal(1), "want OKP")
		Expect(coseKey.Crv).To(Equal(6), "want Ed25519")
		Expect(coseKey.Alg).To(Equal(COSEAlgEdDSA))
		Expect(coseKey.X).To(HaveLen(32))
	})

	It("defaults to ES256 when no algorithms are specified", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)

		entry, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"example.com", "Example", "user", "User",
			nil,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(entry.PrivateKeyPEM).To(HavePrefix("-----BEGIN PRIVATE KEY-----"), "default algorithm should be ES256 (PKCS#8)")
	})

	It("fills the entry display fields from the request", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)

		entry, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"rp.example.com", "RP Name", "alice", "Alice",
			[]int{COSEAlgES256},
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(entry.Subject).To(Equal("Alice"))
		Expect(entry.RPID).To(Equal("rp.example.com"))
		Expect(entry.RPName).To(Equal("RP Name"))
		Expect(entry.Username).To(Equal("alice"))
	})

	It("refuses an unsupported algorithm", func() {
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, dbpool.NewDatabasePool(nil))
		_, err := svc.CreatePasskey(
			"test-db-uuid",
			"example.com", "Example", "user", "User",
			[]int{COSEAlgPS256}, // RSASSA-PSS not implemented
		)
		Expect(err).To(HaveOccurred())
	})

	It("refuses to run when the service is disabled", func() {
		svc := NewFido2Service(&config.Fido2Config{Enabled: false}, dbpool.NewDatabasePool(nil))
		_, err := svc.CreatePasskey(
			"test-db-uuid",
			"example.com", "Example", "user", "User",
			[]int{COSEAlgES256},
		)
		Expect(err).To(HaveOccurred())
	})

	It("refuses an unknown database", func() {
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, dbpool.NewDatabasePool(nil))
		_, err := svc.CreatePasskey(
			"nonexistent-db-uuid",
			"example.com", "Example", "user", "User",
			[]int{COSEAlgES256},
		)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("FindPasskeysByRPID", func() {
	It("returns no results on an empty pool", func() {
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, dbpool.NewDatabasePool(nil))
		results, err := svc.FindPasskeysByRPID("", "github.com")
		Expect(err).NotTo(HaveOccurred())
		Expect(results).To(BeEmpty())
	})
})

var _ = Describe("NewFido2Service", func() {
	It("wires config and pool", func() {
		cfg := &config.Fido2Config{Enabled: true}
		pool := dbpool.NewDatabasePool(nil)
		svc := NewFido2Service(cfg, pool)
		Expect(svc).NotTo(BeNil())
		Expect(svc.config).To(Equal(cfg))
		Expect(svc.pool).To(Equal(pool))
	})
})

var _ = Describe("COSE algorithm constants", func() {
	It("match the IANA COSE registry values", func() {
		Expect(COSEAlgES256).To(Equal(-7))
		Expect(COSEAlgEdDSA).To(Equal(-8))
		Expect(COSEAlgES256K).To(Equal(-25))
		Expect(COSEAlgPS256).To(Equal(-37))
	})
})

var _ = Describe("authenticator flag constants", func() {
	It("match the CTAP2 flag layout", func() {
		Expect(FlagUP).To(Equal(0x01))
		Expect(FlagUV).To(Equal(0x04))
		Expect(FlagBE).To(Equal(0x08))
		Expect(FlagBS).To(Equal(0x10))
		Expect(FlagAT).To(Equal(0x40))
		Expect(FlagED).To(Equal(0x80))
	})
})

var _ = Describe("SignAssertion", func() {
	hash := func() []byte {
		sum := sha256.Sum256([]byte("client-data-json"))
		return sum[:]
	}

	It("round-trips: create, persist, reopen, find, sign, verify", func() {
		pool, path := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		created, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"github.com", "GitHub", "octocat", "Octocat",
			[]int{COSEAlgES256},
		)
		Expect(err).NotTo(HaveOccurred())
		clientDataHash := hash()

		// Reopen from disk: persistence must be real.
		reopened := reopenPool(path)
		rsvc := NewFido2Service(&config.Fido2Config{Enabled: true}, reopened)

		found, err := rsvc.FindPasskeysByRPID("", "github.com")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(HaveLen(1))
		Expect(found[0].CredentialID).To(Equal(created.CredentialID))
		Expect(found[0].PrivateKeyPEM).To(HavePrefix("-----BEGIN PRIVATE KEY-----"))

		result, err := rsvc.SignAssertion(SignAssertionInput{
			RPID:           "github.com",
			CredentialID:   created.CredentialID,
			ClientDataHash: clientDataHash,
			UserPresent:    true,
		})
		Expect(err).NotTo(HaveOccurred())

		// Verify the signature against the stored COSE public key.
		var cose coseEC2Key
		Expect(cbor.Unmarshal(found[0].PublicKeyCOSE, &cose)).To(Succeed())
		Expect(cose.Alg).To(Equal(COSEAlgES256))
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(cose.X), Y: new(big.Int).SetBytes(cose.Y)}
		digest := sha256.Sum256(append(result.AuthenticatorData, clientDataHash...))
		Expect(ecdsa.VerifyASN1(pub, digest[:], result.Signature)).To(BeTrue())

		Expect(result.SignCount).To(Equal(uint32(1)))
		Expect(result.AuthenticatorData[32] & FlagUP).NotTo(Equal(byte(0)))
		Expect(result.AuthenticatorData[32]&FlagUV).To(Equal(byte(0)), "UV only when the gate verified")
	})

	It("lists every passkey when the RP ID filter is empty", func() {
		// ListPasskeys calls FindPasskeysByRPID with an empty rpID to list
		// everything; an exact-match filter would return nothing.
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		dbUUID := firstPoolUUID(pool)

		for _, rp := range []string{"a.example.com", "b.example.com"} {
			_, err := svc.CreatePasskey(dbUUID, rp, rp, "user", "User", []int{COSEAlgES256})
			Expect(err).NotTo(HaveOccurred())
		}

		found, err := svc.FindPasskeysByRPID(dbUUID, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(HaveLen(2))
		rpIDs := []string{found[0].RPID, found[1].RPID}
		Expect(rpIDs).To(ConsistOf("a.example.com", "b.example.com"))

		one, err := svc.FindPasskeysByRPID(dbUUID, "a.example.com")
		Expect(err).NotTo(HaveOccurred())
		Expect(one).To(HaveLen(1))
	})

	It("keeps the sign counter monotonic across assertions", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		created, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"example.com", "Example", "user", "User",
			[]int{COSEAlgES256},
		)
		Expect(err).NotTo(HaveOccurred())

		first, err := svc.SignAssertion(SignAssertionInput{
			RPID: "example.com", CredentialID: created.CredentialID,
			ClientDataHash: hash(), UserPresent: true,
		})
		Expect(err).NotTo(HaveOccurred())
		second, err := svc.SignAssertion(SignAssertionInput{
			RPID: "example.com", CredentialID: created.CredentialID,
			ClientDataHash: hash(), UserPresent: true,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(first.SignCount).To(Equal(uint32(1)))
		Expect(second.SignCount).To(Equal(uint32(2)))
	})

	It("selects the newest resident credential when no allowList is given", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		for _, name := range []string{"first", "second"} {
			_, err := svc.CreatePasskey(
				firstPoolUUID(pool),
				"example.com", "Example", name, name,
				[]int{COSEAlgES256},
			)
			Expect(err).NotTo(HaveOccurred())
		}

		found, err := svc.FindPasskeysByRPID("", "example.com")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(HaveLen(2))

		// Resident flow must not error on multiple credentials.
		_, err = svc.SignAssertion(SignAssertionInput{
			RPID: "example.com", ClientDataHash: hash(), UserPresent: true,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("refuses to sign without user presence", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		created, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"example.com", "Example", "user", "User",
			[]int{COSEAlgES256},
		)
		Expect(err).NotTo(HaveOccurred())

		_, err = svc.SignAssertion(SignAssertionInput{
			RPID: "example.com", CredentialID: created.CredentialID,
			ClientDataHash: hash(),
		})
		Expect(err).To(MatchError(ContainSubstring("refusing to sign without user presence")))
	})

	It("refuses a credential ID that belongs to another RPID", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		created, err := svc.CreatePasskey(
			firstPoolUUID(pool),
			"github.com", "GitHub", "user", "User",
			[]int{COSEAlgES256},
		)
		Expect(err).NotTo(HaveOccurred())

		_, err = svc.SignAssertion(SignAssertionInput{
			RPID: "evil.example.com", CredentialID: created.CredentialID,
			ClientDataHash: hash(), UserPresent: true,
		})
		Expect(err).To(HaveOccurred(), "RP binding must hold at lookup")
	})

	It("refuses a malformed client data hash", func() {
		pool, _ := newTestPoolWithDB()
		svc := NewFido2Service(&config.Fido2Config{Enabled: true}, pool)
		_, err := svc.SignAssertion(SignAssertionInput{
			RPID: "example.com", ClientDataHash: []byte{1, 2, 3}, UserPresent: true,
		})
		Expect(err).To(MatchError(ContainSubstring("client data hash must be 32 bytes")))
	})
})

// canonicalCOSESpecs pins the exact COSE wire bytes. Chrome's CBOR
// reader rejects maps whose keys are not strictly monotonic (CTAP
// canonical order: uint keys ascending, then negative keys ascending),
// and the P-256 coordinates must be the fixed 32-byte field width —
// big.Int.Bytes() strips leading zeros, so the encoder must pad.
var _ = Describe("COSE public key encoding", func() {
	It("encodes the EC2 key in CTAP canonical key order", func() {
		scalar := make([]byte, 32)
		scalar[31] = 1
		x, y := elliptic.P256().ScalarBaseMult(scalar)
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		encoded, err := encodeECDSAPublicKey(pub)
		Expect(err).NotTo(HaveOccurred())

		// map(5){1:2, 3:-7, -1:1, -2:x(32), -3:y(32)} — keys must appear
		// in exactly this order; alg (key 3) sorts before the negative
		// keys.
		gx := "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
		gy := "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
		want, err := hex.DecodeString("a501020326" + "2001" + "215820" + gx + "225820" + gy)
		Expect(err).NotTo(HaveOccurred())
		Expect(encoded).To(Equal(want),
			"EC2 COSE key must be canonically ordered (1, 3, -1, -2, -3)")
	})

	It("encodes the OKP key in CTAP canonical key order", func() {
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
		pub := priv.Public().(ed25519.PublicKey)
		encoded, err := encodeEd25519PublicKey(pub)
		Expect(err).NotTo(HaveOccurred())

		// map(4){1:1, 3:-8, -1:6, -2:x(32)} — keys 01, 03 27, 20 06,
		// 21 58 20 in exactly this order.
		seedPub := hex.EncodeToString(pub)
		want, err := hex.DecodeString("a401010327" + "2006" + "215820" + seedPub)
		Expect(err).NotTo(HaveOccurred())
		Expect(encoded).To(Equal(want),
			"OKP COSE key must be canonically ordered (1, 3, -1, -2)")
	})

	It("left-pads P-256 coordinates to the fixed 32-byte field width", func() {
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
		encoded, err := encodeECDSAPublicKey(pub)
		Expect(err).NotTo(HaveOccurred())

		var key coseEC2Key
		Expect(cbor.Unmarshal(encoded, &key)).To(Succeed())
		Expect(key.X).To(HaveLen(32), "RFC 9052: P-256 x is 32 bytes, zero-padded")
		Expect(key.Y).To(HaveLen(32), "RFC 9052: P-256 y is 32 bytes, zero-padded")
		Expect(key.X[31]).To(Equal(byte(1)), "small coordinate value preserved")
	})

	It("never emits a short coordinate for generated keys", func() {
		for i := 0; i < 128; i++ {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			encoded, err := encodeECDSAPublicKey(&priv.PublicKey)
			Expect(err).NotTo(HaveOccurred())
			var key coseEC2Key
			Expect(cbor.Unmarshal(encoded, &key)).To(Succeed())
			Expect(key.X).To(HaveLen(32))
			Expect(key.Y).To(HaveLen(32))
		}
	})
})
