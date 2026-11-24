//go:build linux

package secretservice

import (
	"log/slog"
	"sync"

	"github.com/godbus/dbus/v5"
)

// Prompt implements org.freedesktop.Secret.Prompt.
// Per the Secret Service spec the Completed signal carries a dismissed flag
// and a result variant (an object path for unlock/lock operations).
type Prompt struct {
	conn      *dbus.Conn
	path      dbus.ObjectPath
	completed chan struct{}
	dismissed bool
	result    dbus.Variant
	closeOnce sync.Once
}

// NewPrompt creates a new Prompt object.
func NewPrompt(conn *dbus.Conn, path dbus.ObjectPath) *Prompt {
	return &Prompt{
		conn:      conn,
		path:      path,
		completed: make(chan struct{}),
	}
}

// Path returns the DBus object path of this prompt.
func (p *Prompt) Path() dbus.ObjectPath {
	return p.path
}

// complete emits the Completed signal exactly once.
func (p *Prompt) complete(dismissed bool) {
	p.closeOnce.Do(func() {
		p.dismissed = dismissed
		// The result variant is an object path per the spec; "/" means none.
		p.result = dbus.MakeVariant(dbus.ObjectPath("/"))
		if p.conn != nil {
			if err := p.conn.Emit(p.path, "org.freedesktop.Secret.Prompt.Completed",
				p.dismissed, p.result); err != nil {
				slog.Warn("failed to emit Prompt.Completed signal",
					"path", p.path, "error", err)
			}
		}
		close(p.completed)
	})
}

// Prompt completes the prompt. kpxcd performs no interactive operation
// here, so it completes immediately with an empty result.
func (p *Prompt) Prompt(windowID string) *dbus.Error {
	go p.complete(false)
	return nil
}

// Dismiss cancels the prompt.
func (p *Prompt) Dismiss() *dbus.Error {
	p.complete(true)
	return nil
}

// Done returns a channel that is closed when the prompt completes.
func (p *Prompt) Done() <-chan struct{} {
	return p.completed
}
