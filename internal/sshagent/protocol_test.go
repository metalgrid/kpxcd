//go:build linux

package sshagent

import (
	"bytes"
	"encoding/binary"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/metalgrid/kpxcd/internal/config"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("readMessage/writeMessage", func() {
	DescribeTable("round-trips a message through the length prefix",
		func(msg []byte) {
			var buf bytes.Buffer
			Expect(writeMessage(&buf, msg)).To(Succeed())
			got, err := readMessage(&buf)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(msg))
		},
		Entry("single request byte", []byte{SSHAgentCRequestIdentities}),
		Entry("identities answer", []byte{SSHAgentIdentitiesAnswer, 0x00, 0x00, 0x00, 0x01}),
		Entry("plain text", []byte("hello world")),
		Entry("large payload", make([]byte, 1024)),
	)

	It("writes the 4-byte big-endian length prefix", func() {
		msg := []byte{0x01, 0x02, 0x03}
		var buf bytes.Buffer
		Expect(writeMessage(&buf, msg)).To(Succeed())

		data := buf.Bytes()
		Expect(data).To(HaveLen(7)) // 4 header + 3 payload
		Expect(binary.BigEndian.Uint32(data[:4])).To(Equal(uint32(3)))
		Expect(data[4:]).To(Equal(msg))
	})

	It("refuses messages exceeding maxMessageLen", func() {
		var buf bytes.Buffer
		// Write a header claiming 9 MiB.
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, 9*1024*1024)
		buf.Write(hdr)
		buf.Write(make([]byte, 100)) // enough bytes for the header to be read

		_, err := readMessage(&buf)
		Expect(err).To(HaveOccurred())
	})

	It("refuses zero-length messages", func() {
		var buf bytes.Buffer
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, 0)
		buf.Write(hdr)

		_, err := readMessage(&buf)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("encodeIdentitiesAnswer", func() {
	It("formats blobs and comments as an SSH_AGENT_IDENTITIES_ANSWER message", func() {
		blobs := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06, 0x07},
		}
		comments := []string{"key1", "key2"}

		result := encodeIdentitiesAnswer(blobs, comments)

		Expect(result[0]).To(Equal(byte(SSHAgentIdentitiesAnswer)))
		Expect(binary.BigEndian.Uint32(result[1:5])).To(Equal(uint32(2)))

		str1, rest1 := decodeString(result[5:])
		Expect(str1).NotTo(BeNil())
		Expect(str1).To(Equal(blobs[0]))

		comment1, rest2 := decodeString(rest1)
		Expect(comment1).NotTo(BeNil())
		Expect(string(comment1)).To(Equal("key1"))

		str2, rest3 := decodeString(rest2)
		Expect(str2).NotTo(BeNil())
		Expect(str2).To(Equal(blobs[1]))

		comment2, _ := decodeString(rest3)
		Expect(comment2).NotTo(BeNil())
		Expect(string(comment2)).To(Equal("key2"))
	})

	It("defaults missing comments to empty strings", func() {
		blobs := [][]byte{{0x01, 0x02}, {0x03, 0x04}}
		comments := []string{"only_one"}

		result := encodeIdentitiesAnswer(blobs, comments)

		// Skip message type (1 byte) and count (4 bytes).
		pos := 5

		// First key + comment.
		_, rest := decodeString(result[pos:]) // blob
		pos = len(result) - len(rest)
		c1, rest := decodeString(result[pos:])
		pos = len(result) - len(rest)
		Expect(string(c1)).To(Equal("only_one"))

		// Second key + empty comment.
		_, rest = decodeString(result[pos:]) // blob
		pos = len(result) - len(rest)
		c2, _ := decodeString(result[pos:])
		Expect(c2).NotTo(BeNil())
		Expect(c2).To(BeEmpty(), "second comment should be empty")
	})
})

var _ = Describe("decodeMessageType", func() {
	DescribeTable("splits type byte and payload",
		func(input []byte, wantType byte, wantPayload []byte) {
			gotType, gotPayload := decodeMessageType(input)
			Expect(gotType).To(Equal(wantType))
			Expect(gotPayload).To(Equal(wantPayload))
		},
		Entry("normal message", []byte{0x11, 0x02, 0x03}, byte(0x11), []byte{0x02, 0x03}),
		Entry("single byte", []byte{0x05}, byte(0x05), nil),
		Entry("empty input", []byte{}, byte(0), nil),
	)
})

var _ = Describe("decodeString", func() {
	It("parses length-prefixed strings", func() {
		gotStr, gotRest := decodeString(append([]byte{0x00, 0x00, 0x00, 0x05}, []byte("hello")...))
		Expect(gotStr).To(Equal([]byte("hello")))
		Expect(gotRest).To(BeEmpty())
	})

	It("parses an empty string", func() {
		gotStr, gotRest := decodeString([]byte{0x00, 0x00, 0x00, 0x00})
		Expect(gotStr).To(Equal([]byte{}))
		Expect(gotRest).To(BeEmpty())
	})

	It("returns the unparsed remainder", func() {
		input := append(append([]byte{0x00, 0x00, 0x00, 0x03}, []byte("abc")...), 0xFF, 0xFE)
		gotStr, gotRest := decodeString(input)
		Expect(gotStr).To(Equal([]byte("abc")))
		Expect(gotRest).To(Equal([]byte{0xFF, 0xFE}))
	})

	DescribeTable("refuses invalid input with a nil string",
		func(input []byte) {
			gotStr, _ := decodeString(input)
			Expect(gotStr).To(BeNil(), "expected nil string for invalid input")
		},
		Entry("too short for length", []byte{0x00, 0x00, 0x01}),
		Entry("length exceeds data", append([]byte{0x00, 0x00, 0x00, 0x10}, []byte("short")...)),
		Entry("nil input", nil),
	)
})

var _ = Describe("encodeString", func() {
	DescribeTable("appends a length-prefixed string",
		func(data []byte) {
			var buf []byte
			buf = encodeString(buf, data)
			Expect(buf).To(HaveLen(4 + len(data)))
			Expect(binary.BigEndian.Uint32(buf[:4])).To(Equal(uint32(len(data))))
			Expect(buf[4:]).To(Equal(data))
		},
		Entry("hello", []byte("hello")),
		Entry("empty", []byte{}),
		Entry("binary data", []byte{0x00, 0xFF, 0x80}),
	)
})

var _ = Describe("encodeUint32", func() {
	DescribeTable("appends a big-endian uint32",
		func(value uint32, want []byte) {
			Expect(encodeUint32(nil, value)).To(Equal(want))
		},
		Entry("zero", uint32(0x00000000), []byte{0x00, 0x00, 0x00, 0x00}),
		Entry("one", uint32(0x00000001), []byte{0x00, 0x00, 0x00, 0x01}),
		Entry("0xFF", uint32(0x000000FF), []byte{0x00, 0x00, 0x00, 0xFF}),
		Entry("0xFFFF", uint32(0x0000FFFF), []byte{0x00, 0x00, 0xFF, 0xFF}),
		Entry("0xFFFFFF", uint32(0x00FFFFFF), []byte{0x00, 0xFF, 0xFF, 0xFF}),
		Entry("max", uint32(0xFFFFFFFF), []byte{0xFF, 0xFF, 0xFF, 0xFF}),
		Entry("0x12345678", uint32(0x12345678), []byte{0x12, 0x34, 0x56, 0x78}),
	)
})

var _ = Describe("AgentServer.processMessage", func() {
	It("answers an extension request with SSH_AGENT_FAILURE and stays open", func() {
		s := &AgentServer{}
		resp, err := s.processMessage([]byte{SSHAgentCExtension})
		Expect(err).NotTo(HaveOccurred())
		Expect(resp).To(Equal([]byte{SSHAgentFailure}))
	})
})

var _ = Describe("signatureAlgorithmForFlags", func() {
	DescribeTable("maps sign flags to algorithms",
		func(flags uint32, want string, wantErr bool) {
			got, err := signatureAlgorithmForFlags(flags)
			if wantErr {
				Expect(err).To(HaveOccurred())
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))
		},
		Entry("default", uint32(0), "", false),
		Entry("rsa sha256", uint32(SSHAgentSignFlagRSASHA256), ssh.KeyAlgoRSASHA256, false),
		Entry("rsa sha512", uint32(SSHAgentSignFlagRSASHA512), ssh.KeyAlgoRSASHA512, false),
		Entry("reserved", uint32(SSHAgentSignFlagReserved), "", true),
		Entry("conflicting", uint32(SSHAgentSignFlagRSASHA256|SSHAgentSignFlagRSASHA512), "", true),
		Entry("unknown", uint32(0x80), "", true),
	)
})

// FuzzReadMessage verifies that readMessage never panics on arbitrary input.
func FuzzReadMessage(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add(append([]byte{0x00, 0x00, 0x00, 0x05}, []byte("hello")...))
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := bytes.NewReader(data)
		_, _ = readMessage(buf)
	})
}

// FuzzDecodeString verifies that decodeString never panics on arbitrary input.
func FuzzDecodeString(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add(append([]byte{0x00, 0x00, 0x00, 0x05}, []byte("hello")...))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeString(data)
	})
}

// FuzzProcessMessage verifies that processMessage never panics on arbitrary
// SSH agent payloads.
func FuzzProcessMessage(f *testing.F) {
	f.Add([]byte{SSHAgentCRequestIdentities})
	f.Add([]byte{SSHAgentCRemoveAllIdentities})
	f.Add([]byte{SSHAgentCExtension, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		s := &AgentServer{manager: NewIdentityManager(&config.SSHAgentConfig{})}
		_, _ = s.processMessage(data)
	})
}
