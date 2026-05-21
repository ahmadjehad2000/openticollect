package logbuf

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestBufferCapturesAndOrdersNewestFirst(t *testing.T) {
	b := New(100)
	log := slog.New(b.Handler(slog.NewTextHandler(io.Discard, nil)))

	log.Info("first")
	log.Warn("second", "collector", "otx")
	log.Error("third")

	entries := b.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Message != "third" || entries[2].Message != "first" {
		t.Fatalf("entries not newest-first: %#v", entries)
	}
	if entries[0].Level != "ERROR" {
		t.Fatalf("level = %q, want ERROR", entries[0].Level)
	}
	if !strings.Contains(entries[1].Attrs, "collector=otx") {
		t.Fatalf("attrs not captured: %q", entries[1].Attrs)
	}
}

func TestBufferRingCap(t *testing.T) {
	b := New(5)
	log := slog.New(b.Handler(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 20; i++ {
		log.Info("msg")
	}
	if got := len(b.Entries()); got != 5 {
		t.Fatalf("ring should cap at 5, got %d", got)
	}
}

func TestBufferCapturesWithAttrs(t *testing.T) {
	b := New(10)
	log := slog.New(b.Handler(slog.NewTextHandler(io.Discard, nil))).With("source", "scheduler")
	log.Info("ran")

	e := b.Entries()
	if len(e) != 1 || !strings.Contains(e[0].Attrs, "source=scheduler") {
		t.Fatalf("With() attrs not captured: %#v", e)
	}
}
