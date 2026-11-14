//go:build linux

package fido2

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("polkit subject details", func() {
	It("encodes the exact GVariant types polkitd looks up", func() {
		details := polkitSubjectDetails(63908, 1000, 12345)
		Expect(details["pid"].Signature().String()).To(Equal("u"),
			"polkitd looks pid up as uint32; any other type rejects the whole subject and no prompt is routed")
		Expect(details["uid"].Signature().String()).To(Equal("i"),
			"polkitd looks uid up as int32 (polkit encodes uid as int32 with -1 for unknown)")
		Expect(details["start-time"].Signature().String()).To(Equal("t"), "start-time must be uint64")
	})

	It("omits start-time when the process start time cannot be read", func() {
		details := polkitSubjectDetails(1, 0, 0)
		Expect(details).NotTo(HaveKey("start-time"),
			"polkit only accepts a nonzero start-time")
	})
})
