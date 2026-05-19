//go:build linux

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/coreos/go-systemd/v22/journal"
)

// journaldHandler is a slog.Handler that writes to systemd journal.
type journaldHandler struct {
	level slog.Leveler
}

// newJournaldHandler creates a slog.Handler that writes to systemd journal.
func newJournaldHandler(level slog.Level) *journaldHandler {
	return &journaldHandler{level: level}
}

func (h *journaldHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *journaldHandler) Handle(_ context.Context, r slog.Record) error {
	priority := journal.PriInfo
	switch r.Level {
	case slog.LevelDebug:
		priority = journal.PriDebug
	case slog.LevelInfo:
		priority = journal.PriInfo
	case slog.LevelWarn:
		priority = journal.PriWarning
	case slog.LevelError:
		priority = journal.PriErr
	}

	vars := map[string]string{
		"MESSAGE":  r.Message,
		"PRIORITY": fmt.Sprintf("%d", priority),
	}

	r.Attrs(func(a slog.Attr) bool {
		vars[strings.ToUpper(a.Key)] = a.Value.String()
		return true
	})

	return journal.Send(r.Message, priority, vars)
}

func (h *journaldHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Journald handler doesn't support attrs natively in this simple impl.
	return h
}

func (h *journaldHandler) WithGroup(name string) slog.Handler {
	return h
}
