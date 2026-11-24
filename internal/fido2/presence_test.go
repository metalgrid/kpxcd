//go:build linux

package fido2

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/metalgrid/kpxcd/internal/fido2/hid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeAuthorization records the actual godbus boundary, without a bus or agent.
type authorizationInvocation struct {
	ctx    context.Context
	method string
	flags  dbus.Flags
	args   []any
	call   *dbus.Call
}

type fakeAuthorization struct {
	calls    chan authorizationInvocation
	closed   chan struct{}
	dispatch func(authorizationInvocation)
}

func newFakeAuthorization() *fakeAuthorization {
	return &fakeAuthorization{calls: make(chan authorizationInvocation, 4), closed: make(chan struct{})}
}

func (f *fakeAuthorization) GoWithContext(ctx context.Context, method string, flags dbus.Flags, done chan *dbus.Call, args ...any) *dbus.Call {
	call := &dbus.Call{Done: done}
	invocation := authorizationInvocation{ctx, method, flags, args, call}
	f.calls <- invocation
	if f.dispatch != nil {
		f.dispatch(invocation)
	}
	return call
}

func (f *fakeAuthorization) Close() error { close(f.closed); return nil }

func replyAuthorization(i authorizationInvocation, authorized bool, err error) {
	i.call.Err = err
	i.call.Body = []any{[]any{authorized, false, map[string]string{}}}
	i.call.Done <- i.call
}

var _ = Describe("Step 6 authorization lifecycle", func() {
	var fake *fakeAuthorization
	var gate *PresenceGate
	var ctx context.Context
	var cancel context.CancelFunc
	var result chan hid.Approval
	start := func() {
		go func() {
			result <- gate.Approve(ctx, hid.Operation{Kind: hid.OperationRegister, RPID: "private.example", UserVerification: true})
		}()
	}
	BeforeEach(func() {
		fake = newFakeAuthorization()
		gate = &PresenceGate{connect: func(context.Context) (authorizationConnection, error) { return fake, nil }}
		ctx, cancel = context.WithCancel(context.Background())
		DeferCleanup(cancel)
		result = make(chan hid.Approval, 1)
	})
	It("does not connect or dispatch when already canceled", func() {
		gate.connect = func(context.Context) (authorizationConnection, error) {
			Fail("connected after cancellation")
			return nil, nil
		}
		cancel()
		Expect(gate.Approve(ctx, hid.Operation{})).To(BeZero())
	})
	It("closes without dispatch if cancellation wins connection setup", func() {
		gate.connect = func(context.Context) (authorizationConnection, error) { cancel(); return fake, nil }
		Expect(gate.Approve(ctx, hid.Operation{})).To(BeZero())
		Expect(fake.closed).To(BeClosed())
		Expect(fake.calls).NotTo(Receive())
	})
	It("sends typed self subject, action, empty safe details, interaction flag and unique ID", func() {
		start()
		var check authorizationInvocation
		Eventually(fake.calls).Should(Receive(&check))
		Expect(check.method).To(Equal("org.freedesktop.PolicyKit1.Authority.CheckAuthorization"))
		Expect(check.flags).To(BeZero())
		Expect(check.args).To(HaveLen(5))
		Expect(dbus.SignatureOf(check.args...).String()).To(Equal("(sa{sv})sa{ss}us"))
		Expect(check.args[1]).To(Equal("org.keepassxc.daemon.passkey.create"))
		Expect(check.args[2]).To(Equal(map[string]string{}))
		Expect(check.args[3]).To(Equal(uint32(1)))
		Expect(check.args[4]).NotTo(BeEmpty())
		replyAuthorization(check, true, nil)
		Eventually(result).Should(Receive(Equal(hid.Approval{Approved: true, UserPresence: true, UserVerification: true})))
		Eventually(fake.closed).Should(BeClosed())
		Expect(fake.calls).NotTo(Receive())
		Eventually(check.ctx.Done()).Should(BeClosed())
	})
	DescribeTable("refuses terminal errors and denials without inventing approval", func(authorized bool, err error) {
		start()
		var check authorizationInvocation
		Eventually(fake.calls).Should(Receive(&check))
		replyAuthorization(check, authorized, err)
		Eventually(result).Should(Receive(BeZero()))
		Eventually(fake.closed).Should(BeClosed())
	}, Entry("denial", false, nil), Entry("D-Bus error", false, errors.New("refused")), Entry("success bit with error", true, errors.New("failed")))
	It("refuses malformed replies", func() {
		start()
		var check authorizationInvocation
		Eventually(fake.calls).Should(Receive(&check))
		check.call.Body = []any{"malformed"}
		check.call.Done <- check.call
		Eventually(result).Should(Receive(BeZero()))
		Eventually(fake.closed).Should(BeClosed())
	})
	It("cancels the pending prompt on the same live connection before closing", func() {
		start()
		var check, cleanup authorizationInvocation
		Eventually(fake.calls).Should(Receive(&check))
		cancel()
		Eventually(fake.calls).Should(Receive(&cleanup))
		Expect(cleanup.method).To(Equal("org.freedesktop.PolicyKit1.Authority.CancelCheckAuthorization"))
		Expect(cleanup.flags).To(BeZero())
		Expect(cleanup.args).To(Equal([]any{check.args[4]}))
		Expect(cleanup.ctx.Err()).NotTo(HaveOccurred())
		_, bounded := cleanup.ctx.Deadline()
		Expect(bounded).To(BeTrue())
		Expect(fake.closed).NotTo(BeClosed())
		Expect(result).NotTo(Receive())
		replyAuthorization(check, true, nil) // late approval never escapes
		cleanup.call.Done <- cleanup.call
		Eventually(result).Should(Receive(BeZero()))
		Eventually(fake.closed).Should(BeClosed())
	})
	It("orders cancellation after a check whose dispatch was still in progress", func() {
		entered, release := make(chan struct{}), make(chan struct{})
		fake.dispatch = func(i authorizationInvocation) {
			if i.method == authorityInterface+"CheckAuthorization" {
				close(entered)
				<-release
			}
		}
		start()
		Eventually(entered).Should(BeClosed())
		var check, cleanup authorizationInvocation
		Eventually(fake.calls).Should(Receive(&check))
		cancel()
		Expect(fake.calls).NotTo(Receive())
		close(release)
		Eventually(fake.calls).Should(Receive(&cleanup))
		Expect(cleanup.args).To(Equal([]any{check.args[4]}))
		cleanup.call.Done <- cleanup.call
		Eventually(result).Should(Receive(BeZero()))
	})
	It("discards success that races cancellation just before reply delivery", func() {
		fake.dispatch = func(i authorizationInvocation) {
			if i.method == authorityInterface+"CheckAuthorization" {
				cancel()
				replyAuthorization(i, true, nil)
			} else {
				i.call.Done <- i.call
			}
		}
		start()
		Eventually(result).Should(Receive(BeZero()))
		Eventually(fake.closed).Should(BeClosed())
	})
	It("bounds cleanup when cancellation is not acknowledged", func() {
		start()
		Eventually(fake.calls).Should(Receive())
		cancel()
		var cleanup authorizationInvocation
		Eventually(fake.calls).Should(Receive(&cleanup))
		Eventually(result, 4*time.Second).Should(Receive(BeZero()))
		Expect(cleanup.ctx.Err()).To(MatchError(context.DeadlineExceeded))
		Eventually(fake.closed).Should(BeClosed())
	})
	It("cancels on a deadline and tolerates a cancel error", func() {
		ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
		DeferCleanup(cancel)
		start()
		var check, cleanup authorizationInvocation
		Eventually(fake.calls).Should(Receive(&check))
		Eventually(fake.calls).Should(Receive(&cleanup))
		cleanup.call.Err = errors.New("already completed")
		cleanup.call.Done <- cleanup.call
		Eventually(result).Should(Receive(BeZero()))
		Eventually(fake.closed).Should(BeClosed())
	})
	It("keeps simultaneous operation IDs and cancellation connections separate", func() {
		second := newFakeAuthorization()
		other := &PresenceGate{connect: func(context.Context) (authorizationConnection, error) { return second, nil }}
		otherResult := make(chan hid.Approval, 1)
		var wg sync.WaitGroup
		wg.Go(func() { otherResult <- other.Approve(context.Background(), hid.Operation{}) })
		start()
		var first, next, cleanup authorizationInvocation
		Eventually(fake.calls).Should(Receive(&first))
		Eventually(second.calls).Should(Receive(&next))
		Expect(first.args[4]).NotTo(Equal(next.args[4]))
		Expect(next.args[1]).To(Equal("org.keepassxc.daemon.passkey.assert"))
		cancel()
		Eventually(fake.calls).Should(Receive(&cleanup))
		cleanup.call.Done <- cleanup.call
		Eventually(result).Should(Receive(BeZero()))
		Expect(second.closed).NotTo(BeClosed())
		Expect(second.calls).NotTo(Receive())
		replyAuthorization(next, true, nil)
		Eventually(otherResult).Should(Receive(Equal(hid.Approval{Approved: true, UserPresence: true, UserVerification: true})))
		wg.Wait()
	})
	It("closes admission, cancels the prompt and waits for same-connection cleanup", func() {
		start()
		var check, cleanup authorizationInvocation
		Eventually(fake.calls).Should(Receive(&check))
		closed := make(chan struct{})
		go func() { gate.Close(); close(closed) }()
		Eventually(fake.calls).Should(Receive(&cleanup))
		Expect(cleanup.args).To(Equal([]any{check.args[4]}))
		Expect(fake.closed).NotTo(BeClosed())
		Expect(closed).NotTo(BeClosed())
		Expect(gate.Approve(context.Background(), hid.Operation{})).To(BeZero())
		Expect(fake.calls).NotTo(Receive())
		cleanup.call.Done <- cleanup.call
		Eventually(closed).Should(BeClosed())
		Expect(fake.closed).To(BeClosed())
		Eventually(result).Should(Receive(BeZero()))
		gate.Close() // idempotent, no second connection close
	})
	It("serializes admission against concurrent shutdown without Add/Wait races", func() {
		gate.connect = func(context.Context) (authorizationConnection, error) {
			connection := newFakeAuthorization()
			connection.dispatch = func(i authorizationInvocation) {
				if i.method == authorityInterface+"CheckAuthorization" {
					replyAuthorization(i, true, nil)
				} else {
					i.call.Done <- i.call
				}
			}
			return connection, nil
		}
		begin := make(chan struct{})
		finished := make(chan struct{})
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() { <-begin; gate.Approve(context.Background(), hid.Operation{}) })
		}
		wg.Go(func() { <-begin; gate.Close() })
		go func() { wg.Wait(); close(finished) }()
		close(begin)
		Eventually(finished).Should(BeClosed())
		gate.mu.Lock()
		Expect(gate.pending).To(BeEmpty())
		Expect(gate.closed).To(BeTrue())
		gate.mu.Unlock()
	})
	It("refuses unavailable authorization without a prompt", func() {
		gate.connect = func(context.Context) (authorizationConnection, error) { return nil, errors.New("unavailable") }
		Expect(gate.Approve(ctx, hid.Operation{})).To(BeZero())
	})
})

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
