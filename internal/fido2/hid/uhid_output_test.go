//go:build linux

package hid

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// rawOutput independently models evt.Data after the library removes event type.
// Literal offsets pin the Linux packed ABI, independently of parser constants.
func rawOutput(report []byte) []byte {
	raw := bytes.Repeat([]byte{0xa5}, 4376)
	copy(raw[:4096], report)
	raw[4096], raw[4097] = byte(len(report)), byte(len(report)>>8)
	raw[4098] = 1
	return raw
}

var _ = Describe("Step 4 UHID output adapter", func() {
	DescribeTable("preserves actual report lengths without reading union padding", func(size int) {
		payload := bytes.Repeat([]byte{0x42}, size)
		report, err := parseUHIDOutput(rawOutput(payload))
		Expect(err).NotTo(HaveOccurred())
		Expect(report).To(Equal(payload))
	}, Entry("one", 1), Entry("unaddressable", 3), Entry("short", 63), Entry("64", 64), Entry("long", 66), Entry("maximum", 4096))

	It("normalizes only an exact zero-prefixed 65-byte report and owns its storage", func() {
		payload := bytes.Repeat([]byte{0x42}, 64)
		for _, input := range [][]byte{payload, append([]byte{0}, payload...)} {
			raw := rawOutput(input)
			report, err := parseUHIDOutput(raw)
			Expect(err).NotTo(HaveOccurred())
			clear(raw)
			Expect(report).To(Equal(payload))
		}
	})

	DescribeTable("rejects envelopes without a trustworthy report", func(raw []byte, message string) {
		report, err := parseUHIDOutput(raw)
		Expect(err).To(MatchError(ContainSubstring(message)))
		Expect(report).To(BeNil())
	},
		Entry("absent", nil, "truncated"),
		Entry("report only", make([]byte, 64), "truncated"),
		Entry("missing size", make([]byte, 4096), "truncated"),
		Entry("partial size", make([]byte, 4097), "truncated"),
		Entry("missing type", make([]byte, 4098), "truncated"),
		Entry("zero", rawOutput(nil), "size"),
		Entry("over maximum", rawOutput(make([]byte, 4097)), "size"),
		Entry("nonzero prefix", rawOutput(bytes.Repeat([]byte{1}, 65)), "report ID"),
		Entry("feature", func() []byte { r := rawOutput(make([]byte, 64)); r[4098] = 0; return r }(), "report type"),
		Entry("input", func() []byte { r := rawOutput(make([]byte, 64)); r[4098] = 2; return r }(), "report type"),
		Entry("unknown type", func() []byte { r := rawOutput(make([]byte, 64)); r[4098] = 255; return r }(), "report type"),
	)

	DescribeTable("feeds broadcast INIT through the production adapter and real framing", func(prefix bool) {
		// Literal broadcast CID, INIT, eight-byte nonce; not the device encoder.
		packet := make([]byte, 64)
		copy(packet, []byte{255, 255, 255, 255, 0x86, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
		if prefix {
			packet = append([]byte{0}, packet...)
		}
		report, err := parseUHIDOutput(rawOutput(packet))
		Expect(err).NotTo(HaveOccurred())
		a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
		writer := &fakeWriter{}
		a.writer = writer
		DeferCleanup(a.Close)
		a.handleReport(context.Background(), report)
		Eventually(writer.all, time.Second).Should(HaveLen(1))
		reply := writer.all()[0]
		Expect(reply).To(HaveLen(64))
		Expect(reply[:7]).To(Equal([]byte{255, 255, 255, 255, 0x86, 0, 17}))
		Expect(reply[7:15]).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
		cid := binary.BigEndian.Uint32(reply[15:19])
		Expect(cid).To(Equal(uint32(1)))
		a.mu.Lock()
		allocated := a.channels[cid]
		a.mu.Unlock()
		Expect(allocated).To(BeTrue())
	}, Entry("64-byte declared report with full union padding", false), Entry("65-byte declared zero-ID report with full union padding", true))

	DescribeTable("leaves malformed actual lengths for strict CTAPHID validation", func(size int) {
		packet := make([]byte, size)
		copy(packet, []byte{0, 0, 0, 1, 0x81, 0, 0})
		report, err := parseUHIDOutput(rawOutput(packet))
		Expect(err).NotTo(HaveOccurred())
		Expect(report).To(HaveLen(size))
		a := NewAuthenticator(&stubStore{}, allowGate{}, nil)
		writer := &fakeWriter{}
		a.writer = writer
		DeferCleanup(a.Close)
		a.handleReport(context.Background(), report)
		Eventually(writer.all, time.Second).Should(HaveLen(1))
		Expect(writer.all()[0][:8]).To(Equal([]byte{0, 0, 0, 1, 0xbf, 0, 1, 3}))
	}, Entry("short", 63), Entry("long", 66), Entry("maximum", 4096))
})
