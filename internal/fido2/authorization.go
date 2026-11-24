//go:build linux

package fido2

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const authorizationIOTimeout = 2 * time.Second

// authorizationBus retains the socket so a stalled write can be interrupted.
// godbus GoWithContext writes synchronously; its context only cancels reply
// tracking. godbus Close also waits for that write, so close the socket first.
// All D-Bus authentication, encoding, dispatch and decoding remain in godbus.
// Polkit needs no Unix file descriptor passing.
type authorizationBus struct {
	conn   *dbus.Conn
	wire   net.Conn
	object dbus.BusObject
}

func connectAuthorization(ctx context.Context) (authorizationConnection, error) {
	ctx, cancel := context.WithTimeout(ctx, authorizationIOTimeout)
	defer cancel()
	address := os.Getenv("DBUS_SYSTEM_BUS_ADDRESS")
	if address == "" {
		address = "unix:path=/var/run/dbus/system_bus_socket"
	}
	path, err := authorizationSocket(address)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	wire, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	// Bound the Auth/Hello handshake as well as initial connection setup.
	stop := context.AfterFunc(ctx, func() { _ = wire.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := wire.SetDeadline(deadline); err != nil {
		_ = wire.Close()
		return nil, err
	}
	conn, err := dbus.NewConn(wire)
	if err != nil {
		_ = wire.Close()
		return nil, err
	}
	bus := &authorizationBus{conn: conn, wire: wire, object: conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")}
	if err := conn.Auth(nil); err != nil {
		_ = bus.Close()
		return nil, err
	}
	if err := conn.Hello(); err != nil {
		_ = bus.Close()
		return nil, err
	}
	if ctx.Err() != nil || !stop() {
		_ = bus.Close()
		return nil, fmt.Errorf("fido2: authorization connection canceled")
	}
	if err := wire.SetDeadline(time.Time{}); err != nil {
		_ = bus.Close()
		return nil, err
	}
	return bus, nil
}

func (b *authorizationBus) GoWithContext(ctx context.Context, method string, flags dbus.Flags, done chan *dbus.Call, args ...any) *dbus.Call {
	deadline := time.Now().Add(authorizationIOTimeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := b.wire.SetWriteDeadline(deadline); err != nil {
		call := &dbus.Call{Err: err, Done: done}
		done <- call
		return call
	}
	return b.object.GoWithContext(ctx, method, flags, done, args...)
}

func (b *authorizationBus) Close() error {
	_ = b.wire.Close()
	return b.conn.Close()
}

// authorizationSocket accepts Linux system-bus Unix addresses. Unsupported or
// ambiguous transports fail closed instead of falling back to a different bus.
// The optional GUID does not select the socket, as in godbus's Unix transport.
func authorizationSocket(address string) (string, error) {
	keys, ok := strings.CutPrefix(address, "unix:")
	if !ok || strings.Contains(keys, ";") {
		return "", fmt.Errorf("fido2: authorization requires one Unix system-bus address")
	}
	var path, abstract string
	seen := make(map[string]bool)
	for item := range strings.SplitSeq(keys, ",") {
		key, value, ok := strings.Cut(item, "=")
		if !ok || seen[key] {
			return "", fmt.Errorf("fido2: invalid system-bus address")
		}
		seen[key] = true
		value, err := dbus.UnescapeBusAddressValue(value)
		if err != nil {
			return "", fmt.Errorf("fido2: invalid system-bus address encoding: %w", err)
		}
		switch key {
		case "path":
			path = value
		case "abstract":
			abstract = value
		case "guid":
		default:
			return "", fmt.Errorf("fido2: unsupported system-bus address key")
		}
	}
	if path != "" && abstract == "" && strings.HasPrefix(path, "/") && !strings.ContainsRune(path, 0) {
		return path, nil
	}
	if abstract != "" && path == "" && !strings.ContainsRune(abstract, 0) {
		return "@" + abstract, nil
	}
	return "", fmt.Errorf("fido2: invalid Unix system-bus socket")
}
