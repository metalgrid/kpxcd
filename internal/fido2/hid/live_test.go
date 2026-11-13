//go:build linux

package hid

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Live kernel round-trip: create the virtual device via /dev/uhid, then
// speak CTAPHID to it through the resulting hidraw node — the same path a
// browser takes. Skipped when /dev/uhid is not accessible to the runner.
var _ = Describe("live uhid transport", func() {
	It("answers a CTAPHID_INIT written to the hidraw node", func() {
		if _, err := os.Stat("/dev/uhid"); err != nil {
			Skip("/dev/uhid does not exist")
		}
		f, err := os.OpenFile("/dev/uhid", os.O_RDWR, 0)
		if err != nil {
			Skip("/dev/uhid not accessible to this user (ACL?): " + err.Error())
		}
		f.Close()

		a := NewAuthenticator(&stubStore{creds: true}, allowGate{}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		Expect(a.Start(ctx)).To(Succeed())
		defer a.Close()

		// Find the hidraw node this device instance created; the kernel
		// attaches it asynchronously after UHID_START.
		var nodes []string
		Eventually(func() []string {
			nodes, _ = a.dev.HidrawNodes(ctx)
			return nodes
		}, "5s").ShouldNot(BeEmpty())

		hidraw, err := os.OpenFile(filepath.Join("/dev", filepath.Base(nodes[0])), os.O_RDWR, 0)
		if err != nil {
			Skip("hidraw node not accessible (udev uaccess grant missing): " + err.Error())
		}
		defer hidraw.Close()

		nonce := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
		// Chrome prefixes hidraw writes with a 0x00 report-ID byte for
		// report-ID-less devices; write exactly what Chrome writes.
		req := append([]byte{0x00}, buildRequest(broadcastChannel, cmdInit, nonce)[0]...)
		Expect(req).To(HaveLen(reportSize + 1))
		n, err := hidraw.Write(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(reportSize + 1))

		reply := make([]byte, reportSize)
		read, err := hidraw.Read(reply)
		Expect(err).NotTo(HaveOccurred())
		Expect(read).To(Equal(reportSize))

		Expect(reply[4]).To(Equal(byte(cmdInit | typeInit)))
		payload := reply[7 : 7+17]
		Expect(payload[:8]).To(Equal(nonce))
		newCID := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])
		Expect(newCID).NotTo(Equal(uint32(broadcastChannel)))
	})
})
