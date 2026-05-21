// Package logbuf captures recent slog output into an in-memory ring buffer so
// it can be shown in the web UI.
package logbuf

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Entry is one captured log record, pre-formatted for display.
type Entry struct {
	When    string
	Level   string
	Message string
	Attrs   string
}

// Buffer is a fixed-size, newest-wins ring of log entries.
type Buffer struct {
	mu      sync.Mutex
	entries []Entry
	max     int
}

func New(max int) *Buffer {
	if max < 1 {
		max = 100
	}
	return &Buffer{max: max}
}

func (b *Buffer) add(e Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, e)
	if len(b.entries) > b.max {
		b.entries = b.entries[len(b.entries)-b.max:]
	}
}

// Entries returns the captured log entries, newest first.
func (b *Buffer) Entries() []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Entry, len(b.entries))
	for i, e := range b.entries {
		out[len(b.entries)-1-i] = e
	}
	return out
}

// Handler wraps inner so every log record is also captured into the buffer.
func (b *Buffer) Handler(inner slog.Handler) slog.Handler {
	return &handler{inner: inner, buf: b}
}

type handler struct {
	inner slog.Handler
	buf   *Buffer
	attrs []slog.Attr
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	var sb strings.Builder
	for _, a := range h.attrs {
		sb.WriteString(a.Key + "=" + a.Value.String() + "  ")
	}
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(a.Key + "=" + a.Value.String() + "  ")
		return true
	})
	when := r.Time
	if when.IsZero() {
		when = time.Now()
	}
	h.buf.add(Entry{
		When:    when.Format("2006-01-02 15:04:05"),
		Level:   r.Level.String(),
		Message: r.Message,
		Attrs:   strings.TrimSpace(sb.String()),
	})
	return h.inner.Handle(ctx, r)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	merged := append(append([]slog.Attr{}, h.attrs...), as...)
	return &handler{inner: h.inner.WithAttrs(as), buf: h.buf, attrs: merged}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{inner: h.inner.WithGroup(name), buf: h.buf, attrs: h.attrs}
}
