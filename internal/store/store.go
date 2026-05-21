// Package store is the only package that issues SQL. It wraps a single
// modernc.org/sqlite database opened in WAL mode.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database and applies the schema.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("store: create data dir: %w", err)
		}
	}
	// synchronous(NORMAL) is the SQLite-recommended setting for WAL mode: commits
	// no longer fsync (only checkpoints do), which is durable across app crashes.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrate applies idempotent ALTER TABLE statements for columns added after a
// database may already exist. SQLite has no "ADD COLUMN IF NOT EXISTS", so a
// duplicate-column error is expected and ignored.
func migrate(db *sql.DB) error {
	alters := []string{
		`ALTER TABLE findings ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0`,
	}
	for _, a := range alters {
		if _, err := db.Exec(a); err != nil {
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("store: migrate: %w", err)
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }
