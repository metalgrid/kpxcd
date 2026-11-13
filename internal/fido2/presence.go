//go:build linux

package fido2

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

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
// process subject: auth_self means the desktop polkit agent prompts for
// the user's password. No answer, an error, and a denial are all
// refusals — the gate has no allow-by-default path.
type PresenceGate struct{}

// NewPresenceGate builds the polkit-backed presence gate.
func NewPresenceGate() *PresenceGate { return &PresenceGate{} }

// Approve implements hid.Gate. It honors ctx cancellation: a canceled
// wait is a refusal, and the response to the transport is denial.
func (g *PresenceGate) Approve(ctx context.Context, op hid.Operation) bool {
	action := ActionPasskeyAssert
	if op.Kind == hid.OperationRegister {
		action = ActionPasskeyCreate
	}

	// polkit CheckAuthorization cannot cancel an interactive prompt; the
	// goroutine leaks until the prompt is answered or times out, and its
	// late answer is discarded.
	done := make(chan error, 1)
	go func() { done <- checkPolkitSelf(action) }()

	select {
	case <-ctx.Done():
		slog.Warn("fido2: presence gate canceled", "kind", op.Kind, "rpID", op.RPID)
		return false
	case err := <-done:
		if err != nil {
			slog.Warn("fido2: presence gate refused", "kind", op.Kind, "rpID", op.RPID, "err", err)
			return false
		}
		slog.Info("fido2: presence gate approved", "kind", op.Kind, "rpID", op.RPID)
		return true
	}
}

// checkPolkitSelf asks polkit whether the daemon's own user may perform
// actionID, allowing interactive authentication.
func checkPolkitSelf(actionID string) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("polkit unavailable: connect to system bus: %w", err)
	}
	defer conn.Close()

	pid := os.Getpid()
	subjectDetails := map[string]dbus.Variant{
		"pid": dbus.MakeVariant(pid),
		"uid": dbus.MakeVariant(int32(os.Getuid())),
	}
	if startTime, ok := procStartTime(pid); ok {
		subjectDetails["start-time"] = dbus.MakeVariant(startTime)
	}
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{Kind: "unix-process", Details: subjectDetails}

	const allowUserInteraction uint32 = 1
	obj := conn.Object("org.freedesktop.PolicyKit1", dbus.ObjectPath("/org/freedesktop/PolicyKit1/Authority"))

	var result struct {
		IsAuthorized bool
		IsChallenge  bool
		Details      map[string]string
	}
	call := obj.Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0,
		subject, actionID, map[string]string{}, allowUserInteraction, "")
	if call.Err != nil {
		return fmt.Errorf("polkit authorization failed: %w", call.Err)
	}
	if err := call.Store(&result); err != nil {
		return fmt.Errorf("decode polkit response: %w", err)
	}
	if !result.IsAuthorized {
		return fmt.Errorf("polkit denied action %s", actionID)
	}
	return nil
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
