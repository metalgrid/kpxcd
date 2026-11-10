//go:build linux

package security

import (
	"bytes"
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Alloc/Wipe", func() {
	It("returns locked memory and zeroes it on Wipe", func() {
		b, err := Alloc(32)
		Expect(err).NotTo(HaveOccurred())
		for i := range b {
			b[i] = byte(i + 1)
		}
		Wipe(b)
		Expect(b).To(Equal(make([]byte, 32)))
	})
})

var _ = Describe("SecureString", func() {
	It("supports creation, copy, and destruction", func() {
		ss, err := NewSecureString("hello")
		Expect(err).NotTo(HaveOccurred())
		Expect(ss.Len()).To(Equal(5))
		Expect(string(ss.Bytes())).To(Equal("hello"))
		ss.Destroy()
		Expect(ss.Len()).To(Equal(0), "Destroy should leave length 0")
	})

	It("returns nil bytes for a nil SecureString", func() {
		var ss *SecureString
		Expect(ss.Bytes()).To(BeNil())
		Expect(ss.Len()).To(Equal(0))
	})
})

var _ = Describe("SecureSlice", func() {
	It("allocates, exposes data, and nils the slice on Destroy", func() {
		s, err := NewSecureSlice(16)
		Expect(err).NotTo(HaveOccurred())
		data := s.Data()
		Expect(data).To(HaveLen(16))
		for i := range data {
			data[i] = 0xAA
		}
		s.Destroy()
		Expect(s.Data()).To(BeNil(), "Destroy should nil the slice")
	})
})

var _ = Describe("Mlock/Munlock", func() {
	It("treats empty slices as no-ops", func() {
		Expect(Mlock(nil)).To(Succeed())
		Expect(Munlock(nil)).To(Succeed())
	})
})

var _ = Describe("Memset/Memclr", func() {
	It("fills and clears low-level memory", func() {
		b := make([]byte, 8)
		Memset(b, 0x42)
		Expect(b).To(Equal(bytes.Repeat([]byte{0x42}, 8)))
		Memclr(unsafe.Pointer(&b[0]), len(b))
		Expect(b).To(Equal(make([]byte, 8)))
	})
})

var _ = Describe("SecureBool", func() {
	It("keeps its value until Destroy", func() {
		b := NewSecureBool(true)
		Expect(b.Value()).To(BeTrue())
		b.Destroy()
		Expect(b.Value()).To(BeFalse(), "Destroy should zero the value")

		var nilBool *SecureBool
		Expect(nilBool.Value()).To(BeFalse())
	})
})
