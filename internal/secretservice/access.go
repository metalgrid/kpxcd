//go:build linux

package secretservice

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const actionGetEntrySecret = "org.keepassxc.daemon.get-entry.secret"

var errPolkitUnavailable = errors.New("polkit unavailable")

// CallerInfo describes the D-Bus caller that requested secret material.
type CallerInfo struct {
	Sender  string
	PID     uint32
	UID     uint32
	Exe     string
	Command string
}

// AppName returns the best human-readable caller name we have.
func (c CallerInfo) AppName() string {
	if c.Exe != "" {
		return filepath.Base(c.Exe)
	}
	if c.Command != "" {
		fields := strings.Fields(c.Command)
		if len(fields) > 0 {
			return filepath.Base(fields[0])
		}
	}
	if c.Sender != "" {
		return c.Sender
	}
	return "unknown process"
}

// notifyCacheKey returns a stable identity for the calling app, used to key
// the notification suppression cache. It prefers the executable path, then
// the command line, then the unique D-Bus sender name.
func (c CallerInfo) notifyCacheKey() string {
	if c.Exe != "" {
		return "exe:" + c.Exe
	}
	if c.Command != "" {
		if fields := strings.Fields(c.Command); len(fields) > 0 {
			return "cmd:" + fields[0]
		}
	}
	if c.Sender != "" {
		return "sender:" + c.Sender
	}
	return "unknown"
}

// callerInfo resolves a D-Bus sender to process metadata for logging,
// notifications, and authorization decisions. Failures are non-fatal: callers
// can still be identified by their unique D-Bus sender name.
func (ss *SecretService) callerInfo(sender dbus.Sender) CallerInfo {
	info := CallerInfo{Sender: string(sender)}
	if ss.conn == nil || sender == "" {
		return info
	}

	bus := ss.conn.Object("org.freedesktop.DBus", dbus.ObjectPath("/org/freedesktop/DBus"))

	var pid uint32
	if err := bus.Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, string(sender)).Store(&pid); err != nil {
		slog.Debug("secretservice: failed to resolve caller pid", "sender", string(sender), "error", err)
	} else {
		info.PID = pid
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			info.Exe = exe
		}
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			cmdline = bytes.TrimRight(cmdline, "\x00")
			cmdline = bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '})
			info.Command = string(cmdline)
		}
	}

	var uid uint32
	if err := bus.Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid); err != nil {
		slog.Debug("secretservice: failed to resolve caller uid", "sender", string(sender), "error", err)
	} else {
		info.UID = uid
	}

	return info
}

// authorizeSecretAccess enforces the Secret Service confirmation policy.
func (ss *SecretService) authorizeSecretAccess(caller CallerInfo, item *Item) error {
	cfg := ss.configSnapshot()
	if !cfg.RequireConfirmation {
		return nil
	}
	if caller.PID == 0 {
		slog.Warn("secretservice: confirmation requested but caller process is unknown; denying access",
			"sender", caller.Sender,
			"collection", item.coll.db.Name,
			"item", item.Label())
		return fmt.Errorf("confirmation required but caller process is unknown")
	}

	slog.Debug("secretservice: requesting polkit confirmation",
		"sender", caller.Sender,
		"pid", caller.PID,
		"app", caller.AppName(),
		"exe", caller.Exe,
		"collection", item.coll.db.Name,
		"item", item.Label())

	if err := checkPolkitAuthorization(caller, actionGetEntrySecret); err != nil {
		if errors.Is(err, errPolkitUnavailable) {
			slog.Warn("secretservice: confirmation unavailable; denying secret access",
				"sender", caller.Sender,
				"pid", caller.PID,
				"app", caller.AppName(),
				"collection", item.coll.db.Name,
				"item", item.Label(),
				"error", err)
		}
		return err
	}
	return nil
}

type polkitSubject struct {
	Kind    string
	Details map[string]dbus.Variant
}

type polkitResult struct {
	IsAuthorized bool
	IsChallenge  bool
	Details      map[string]string
}

// checkPolkitAuthorization asks polkit whether caller may perform actionID.
// It allows user interaction so a desktop polkit agent can show the prompt.
func checkPolkitAuthorization(caller CallerInfo, actionID string) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("%w: connect to system bus for polkit: %v", errPolkitUnavailable, err)
	}
	defer conn.Close()

	subjectDetails := map[string]dbus.Variant{
		"pid": dbus.MakeVariant(caller.PID),
	}
	if caller.UID != 0 {
		// polkit expects uid as a signed integer in unix-process subjects.
		subjectDetails["uid"] = dbus.MakeVariant(int32(caller.UID))
	}
	if startTime, ok := procStartTime(caller.PID); ok {
		subjectDetails["start-time"] = dbus.MakeVariant(startTime)
	}

	subject := polkitSubject{
		Kind:    "unix-process",
		Details: subjectDetails,
	}

	const allowUserInteraction uint32 = 1
	obj := conn.Object("org.freedesktop.PolicyKit1", dbus.ObjectPath("/org/freedesktop/PolicyKit1/Authority"))

	var result polkitResult
	// The CheckAuthorization details argument is intentionally empty. Polkit
	// rejects non-root/non-action-owner callers that pass arbitrary details with:
	// "Only trusted callers ... can use CheckAuthorization() and pass details".
	// We keep request context in kpxcd logs/notifications instead.
	call := obj.Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0,
		subject,
		actionID,
		map[string]string{},
		allowUserInteraction,
		"",
	)
	if call.Err != nil {
		// This commonly happens when running from the build directory without
		// installing contrib/polkit/org.keepassxc.daemon.policy.
		return fmt.Errorf("%w: polkit authorization failed: %v", errPolkitUnavailable, call.Err)
	}
	if err := call.Store(&result); err != nil {
		return fmt.Errorf("decode polkit response: %w", err)
	}
	if !result.IsAuthorized {
		return fmt.Errorf("polkit denied action %s", actionID)
	}
	return nil
}

// procStartTime returns /proc/<pid>/stat field 22 (clock ticks after boot).
func procStartTime(pid uint32) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	stat := string(data)
	endComm := strings.LastIndex(stat, ")")
	if endComm == -1 || endComm+2 >= len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[endComm+2:])
	// Fields after comm start at stat field 3. starttime is field 22, so index 19.
	if len(fields) <= 19 {
		return 0, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return start, true
}

// logSecretAccess records a successful secret read without logging the secret.
func (ss *SecretService) logSecretAccess(caller CallerInfo, item *Item, via string) {
	slog.Info("secretservice: secret accessed",
		"via", via,
		"sender", caller.Sender,
		"pid", caller.PID,
		"uid", caller.UID,
		"app", caller.AppName(),
		"exe", caller.Exe,
		"collection", item.coll.db.Name,
		"item", item.Label(),
	)
}

// notifySecretAccess sends a desktop notification about a successful secret
// read. Repeat notifications from the same app are suppressed for the
// configured notify_cache_ttl; the TTL refreshes on each suppressed access.
func (ss *SecretService) notifySecretAccess(caller CallerInfo, item *Item) {
	cfg := ss.configSnapshot()
	if !cfg.NotifyOnAccess || ss.conn == nil {
		return
	}

	if !ss.notifyCache.allow(caller.notifyCacheKey(), time.Duration(cfg.NotifyCacheTTL)*time.Second) {
		slog.Debug("secretservice: suppressed repeat access notification",
			"app", caller.AppName(),
			"item", item.Label(),
			"ttl_seconds", cfg.NotifyCacheTTL)
		return
	}

	app := caller.AppName()
	summary := fmt.Sprintf("%s accessed a secret", app)
	body := fmt.Sprintf("%q from %s", item.Label(), item.coll.db.Name)

	go func() {
		obj := ss.conn.Object("org.freedesktop.Notifications", dbus.ObjectPath("/org/freedesktop/Notifications"))
		hints := map[string]dbus.Variant{
			"desktop-entry": dbus.MakeVariant("kpxcd"),
		}
		var id uint32
		call := obj.Call("org.freedesktop.Notifications.Notify", 0,
			"kpxcd",           // app_name
			uint32(0),         // replaces_id
			"dialog-password", // app_icon
			summary,
			body,
			[]string{}, // actions
			hints,
			int32(5000), // expire_timeout ms
		)
		if call.Err != nil {
			slog.Debug("secretservice: notification failed", "error", call.Err)
			return
		}
		_ = call.Store(&id)
	}()
}
