//go:build linux

package fido2

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("polkit subject details", func() {
	It("encodes the exact GVariant types polkitd looks up", func() {
		details := polkitSubjectDetails(63908, 1000, 12345)
		Expect(details["pid"].Signature().String()).To(Equal("i"),
			"polkitd looks pid up as int32; an int64 variant is silently ignored and no prompt is routed")
		Expect(details["uid"].Signature().String()).To(Equal("i"), "uid must be int32")
		Expect(details["start-time"].Signature().String()).To(Equal("t"), "start-time must be uint64")
	})

	It("omits start-time when the process start time cannot be read", func() {
		details := polkitSubjectDetails(1, 0, 0)
		Expect(details).NotTo(HaveKey("start-time"),
			"polkit only accepts a nonzero start-time")
	})
})
