package store

import (
	"path/filepath"
	"testing"
)

// newTestStore opens a fresh store backed by a temp file.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenAppliesSchema(t *testing.T) {
	s := newTestStore(t)
	var n int
	row := s.db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN
		 ('keywords','findings','source_runs','source_state')`)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n != 4 {
		t.Fatalf("expected 4 tables, got %d", n)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()
	s2, err := Open(path) // reopening must not error on existing tables
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.Close()
}
