//go:build linux

package fido2

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/metalgrid/kpxcd/internal/fido2/hid"
)

// Polkit actions gating passkey operations (defined in
// contrib/polkit/org.keepassxc.daemon.policy).
const (
	ActionPasskeyCreate = "org.keepassxc.daemon.passkey.create"
	ActionPasskeyAssert = "org.keepassxc.daemon.passkey.assert"
)

// PresenceGate implements hid.Gate with polkit. Every operation runs a
// CheckAuthorization with allow-interaction against the daemon's own
// process subject. The auth_self policy requires the user's authentication.
// The system configuration determines the method; any compatible polkit
// agent can handle the prompt. No answer, an error, or a denial refuses
// the operation. The gate has no allow-by-default path.
type PresenceGate struct {
	connect func(context.Context) (authorizationConnection, error)
	mu      sync.Mutex
	closed  bool
	pending map[*approvalWait]struct{}
	wait    sync.WaitGroup
}

type approvalWait struct{ cancel context.CancelFunc }

// NewPresenceGate builds the polkit-backed presence gate.
func NewPresenceGate() *PresenceGate { return &PresenceGate{connect: connectAuthorization} }

// Approve implements hid.Gate. It honors ctx cancellation: a canceled
// wait is a refusal, and the response to the transport is denial.
func (g *PresenceGate) Approve(ctx context.Context, op hid.Operation) hid.Approval {
	action := ActionPasskeyAssert
	if op.Kind == hid.OperationRegister {
		action = ActionPasskeyCreate
	}

	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return hid.Approval{}
	}
	if g.pending == nil {
		g.pending = make(map[*approvalWait]struct{})
	}
	pending := &approvalWait{cancel: cancel}
	g.pending[pending] = struct{}{}
	g.wait.Add(1)
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.pending, pending)
		g.mu.Unlock()
		g.wait.Done()
	}()
	if err := g.check(ctx, action); err != nil || ctx.Err() != nil {
		slog.Debug("fido2: presence gate refused")
		return hid.Approval{}
	}
	// Under the shipped fresh-auth auth_self policy, successful interactive
	// authentication establishes both presence and verification, regardless of
	// the requested subset. Local policy overrides can invalidate this assumption;
	// no particular authentication method is required or inferred.
	return hid.Approval{Approved: true, UserPresence: true, UserVerification: true}
}

// Close cancels pending requests and waits for their bounded cleanup. Admission
// is closed under the same mutex as registration, so Wait cannot race a new Add.
// The daemon waits here before exiting rather than abandoning prompt cleanup.
func (g *PresenceGate) Close() {
	g.mu.Lock()
	g.closed = true
	for pending := range g.pending {
		pending.cancel()
	}
	g.mu.Unlock()
	g.wait.Wait()
}

// polkitSubjectDetails builds the unix-process subject details for
// CheckAuthorization. Variant types matter to polkitd: it looks each
// key up with an exact GVariant type — pid uint32, uid int32,
// start-time uint64 — mirroring polkit's own unix-process encoding.
// Any type mismatch rejects the whole subject and the call never
// routes a prompt. This is a wire-format contract, not live security evidence.
func polkitSubjectDetails(pid uint32, uid int32, startTime uint64) map[string]dbus.Variant {
	details := map[string]dbus.Variant{
		"pid": dbus.MakeVariant(pid),
		"uid": dbus.MakeVariant(uid),
	}
	if startTime != 0 {
		details["start-time"] = dbus.MakeVariant(startTime)
	}
	return details
}

const authorityInterface = "org.freedesktop.PolicyKit1.Authority."

// The fake boundary uses godbus calls unchanged, including their argument types.
// A connection belongs to exactly one check and remains open through cancellation.
type authorizationConnection interface {
	GoWithContext(context.Context, string, dbus.Flags, chan *dbus.Call, ...any) *dbus.Call
	Close() error
}

var authorizationSequence atomic.Uint64

// check asks polkit about this process. Local context cancellation alone only
// abandons a godbus reply; it does not cancel the server's interactive request.
func (g *PresenceGate) check(ctx context.Context, actionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := g.connect(ctx)
	if err != nil {
		slog.Warn("fido2: authorization service unavailable")
		return fmt.Errorf("fido2: connect authorization: %w", err)
	}
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return err
	}

	pid := os.Getpid()
	var startTime uint64
	if st, ok := procStartTime(pid); ok {
		startTime = st
	}
	details := polkitSubjectDetails(uint32(pid), int32(os.Getuid()), startTime)
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{
		Kind:    "unix-process",
		Details: details,
	}

	const allowUserInteraction uint32 = 1
	id := fmt.Sprintf("kpxcd-%d", authorizationSequence.Add(1))
	// Do not pass the operation context to dispatch: cancellation while writing
	// must not let Cancel overtake Check. The adapter bounds each write. Once
	// dispatch returns, cancellation is sent on this same sender connection.
	requestCtx, finish := context.WithCancel(context.Background())
	defer finish()
	if err := ctx.Err(); err != nil {
		return err
	}
	call := conn.GoWithContext(requestCtx, authorityInterface+"CheckAuthorization", 0, make(chan *dbus.Call, 1),
		subject, actionID, map[string]string{}, allowUserInteraction, id)
	select {
	case <-ctx.Done():
		g.cancelAuthorization(conn, id)
		return ctx.Err()
	case call = <-call.Done:
		if err := ctx.Err(); err != nil {
			g.cancelAuthorization(conn, id)
			return err
		}
	}

	var result struct {
		IsAuthorized bool
		IsChallenge  bool
		Details      map[string]string
	}
	if call.Err != nil {
		slog.Warn("fido2: authorization check failed")
		return fmt.Errorf("polkit authorization failed: %w", call.Err)
	}
	if err := call.Store(&result); err != nil {
		slog.Warn("fido2: malformed authorization response")
		return fmt.Errorf("decode polkit response: %w", err)
	}
	if err := ctx.Err(); err != nil {
		g.cancelAuthorization(conn, id)
		return err
	}
	if !result.IsAuthorized {
		return fmt.Errorf("polkit denied action %s", actionID)
	}
	return nil
}

// cancelAuthorization uses a separate bounded context: the ceremony context is
// already canceled. A completed check can race this call and return "not found";
// that is not approval, and no subsequent operation shares this ID or connection.
func (g *PresenceGate) cancelAuthorization(conn authorizationConnection, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), authorizationIOTimeout)
	defer cancel()
	call := conn.GoWithContext(ctx, authorityInterface+"CancelCheckAuthorization", 0, make(chan *dbus.Call, 1), id)
	select {
	case reply := <-call.Done:
		if reply.Err != nil {
			slog.Debug("fido2: authorization cancellation not acknowledged")
		}
	case <-ctx.Done():
		slog.Warn("fido2: authorization cancellation timed out")
	}
}

// procStartTime reads a process start time from /proc, used to make the
// polkit unix-process subject unforgeable (PID reuse protection).
func procStartTime(pid int) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	// Field 22 (1-indexed) is starttime; the comm field may contain
	// spaces, so parse after the closing parenthesis.
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[idx+2:])
	// fields[0] is field 3 (state); starttime is field 22 → index 19.
	if len(fields) < 20 {
		return 0, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return start, true
}
