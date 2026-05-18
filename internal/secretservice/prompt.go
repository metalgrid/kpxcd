//go:build linux

package secretservice

import (
	"log/slog"

	"github.com/godbus/dbus/v5"
)

// Prompt implements org.freedesktop.Secret.Prompt.
// Per the Secret Service spec, Prompt objects are used for operations that
// require user authorization (via Polkit or similar). For now, prompts are
// auto-accepted since Polkit integration is planned for Phase 6.
type Prompt struct {
	conn       *dbus.Conn
	path       dbus.ObjectPath
	completed  chan struct{}
	dismissed  bool
	result     dbus.Variant
}

// NewPrompt creates a new Prompt object.
func NewPrompt(conn *dbus.Conn, path dbus.ObjectPath) *Prompt {
	p := &Prompt{
		conn:      conn,
		path:      path,
		completed: make(chan struct{}),
	}
	return p
}

// Path returns the DBus object path of this prompt.
func (p *Prompt) Path() dbus.ObjectPath {
	return p.path
}

// Prompt prompts the user. For now, it auto-accepts immediately.
// In Phase 6, this will integrate with Polkit for authorization.
func (p *Prompt) Prompt() *dbus.Error {
	// Auto-accept: emit Completed signal immediately.
	go func() {
		p.dismissed = false
		p.result = dbus.MakeVariant("")

		// Emit the Completed signal (skip if no connection, e.g. in tests).
		if p.conn != nil {
			if err := p.conn.Emit(p.path, "org.freedesktop.Secret.Prompt.Completed",
				p.dismissed, p.result); err != nil {
				slog.Warn("failed to emit Prompt.Completed signal",
					"path", p.path, "error", err)
			}
		}

		close(p.completed)
	}()
	return nil
}

// Dismiss cancels the prompt.
func (p *Prompt) Dismiss() *dbus.Error {
	p.dismissed = true
	p.result = dbus.MakeVariant("")

	// Emit the Completed signal with dismissed=true (skip if no connection, e.g. in tests).
	if p.conn != nil {
		if err := p.conn.Emit(p.path, "org.freedesktop.Secret.Prompt.Completed",
			true, p.result); err != nil {
			slog.Warn("failed to emit Prompt.Completed signal (dismiss)",
				"path", p.path, "error", err)
		}
	}

	close(p.completed)
	return nil
}

// Done returns a channel that is closed when the prompt completes.
func (p *Prompt) Done() <-chan struct{} {
	return p.completed
}
