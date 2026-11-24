//go:build linux

package fido2

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Step 6 bounded authorization transport", func() {
	DescribeTable("resolves supported Unix addresses", func(address, want string) {
		path, err := authorizationSocket(address)
		Expect(err).NotTo(HaveOccurred())
		Expect(path).To(Equal(want))
	}, Entry("path", "unix:path=/run/dbus/system_bus_socket", "/run/dbus/system_bus_socket"), Entry("escaped path and guid", "unix:path=/tmp/bus%20test,guid=abc", "/tmp/bus test"), Entry("abstract", "unix:abstract=example", "@example"))
	DescribeTable("refuses unsupported or ambiguous addresses without fallback", func(address string) {
		_, err := authorizationSocket(address)
		Expect(err).To(HaveOccurred())
	}, Entry("TCP", "tcp:host=localhost,port=1"), Entry("list", "unix:path=/a;unix:path=/b"), Entry("both", "unix:path=/a,abstract=b"), Entry("relative", "unix:path=relative"), Entry("empty", "unix:path="), Entry("duplicate", "unix:path=/a,path=/b"), Entry("unknown", "unix:path=/a,other=x"), Entry("encoding", "unix:path=/%xx"), Entry("NUL", "unix:path=/a%00b"))
	It("bounds a blocked godbus dispatch and closes without waiting on its write lock", func() {
		wire, peer := net.Pipe()
		DeferCleanup(peer.Close)
		conn, err := dbus.NewConn(wire)
		Expect(err).NotTo(HaveOccurred())
		bus := &authorizationBus{conn: conn, wire: wire, object: conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")}
		DeferCleanup(bus.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		done := make(chan *dbus.Call, 1)
		dispatched := make(chan struct{})
		go func() {
			bus.GoWithContext(ctx, authorityInterface+"CancelCheckAuthorization", 0, done, "test")
			close(dispatched)
		}()
		Eventually(dispatched).Should(BeClosed())
		var reply *dbus.Call
		Eventually(done).Should(Receive(&reply))
		Expect(reply.Err).To(HaveOccurred())
		closed := make(chan struct{})
		go func() { _ = bus.Close(); close(closed) }()
		Eventually(closed).Should(BeClosed())
	})
	DescribeTable("interrupts a stalled handshake without leaking the setup goroutine", func(deadline bool) {
		path := filepath.Join(GinkgoT().TempDir(), "fake-system-bus")
		listener, err := net.Listen("unix", path)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(listener.Close)
		GinkgoT().Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+path)
		var ctx context.Context
		var cancel context.CancelFunc
		if deadline {
			ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}
		defer cancel()
		result := make(chan error, 1)
		go func() {
			conn, err := connectAuthorization(ctx)
			if conn != nil {
				_ = conn.Close()
			}
			result <- err
		}()
		Expect(listener.(*net.UnixListener).SetDeadline(time.Now().Add(time.Second))).To(Succeed())
		peer, err := listener.Accept()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(peer.Close)
		if !deadline {
			cancel()
		}
		Eventually(result).Should(Receive(HaveOccurred()))
		Expect(peer.SetReadDeadline(time.Now().Add(time.Second))).To(Succeed())
		// Drain the partial auth exchange; the next read must see a closed socket.
		buffer := make([]byte, 4096)
		for {
			_, err = peer.Read(buffer)
			if err != nil {
				break
			}
		}
		Expect(err).To(MatchError("EOF"))
	}, Entry("operation cancellation", false), Entry("operation deadline", true))
	It("does not dial an invalid system bus address", func() {
		GinkgoT().Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unsupported:")
		_, err := connectAuthorization(context.Background())
		Expect(err).To(MatchError(ContainSubstring("Unix system-bus address")))
	})
})
