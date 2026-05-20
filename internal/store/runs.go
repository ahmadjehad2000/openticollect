package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"openticollect/internal/models"
)

func (s *Store) RecordRun(source string, started, finished time.Time, ok bool,
	itemsFetched, findingsCreated int, runErr string) error {
	_, err := s.db.Exec(
		`INSERT INTO source_runs
		 (source, started_at, finished_at, ok, items_fetched, findings_created, error)
		 VALUES(?,?,?,?,?,?,?)`,
		source, started, finished, ok, itemsFetched, findingsCreated, runErr)
	if err != nil {
		return fmt.Errorf("store: record run: %w", err)
	}
	return nil
}

// LatestRun returns the most recent run for a source, or nil if it never ran.
func (s *Store) LatestRun(source string) (*models.Run, error) {
	row := s.db.QueryRow(
		`SELECT id, source, started_at, finished_at, ok, items_fetched,
		        findings_created, error
		 FROM source_runs WHERE source = ? ORDER BY started_at DESC LIMIT 1`, source)
	var (
		r        models.Run
		finished sql.NullTime
		runErr   sql.NullString
	)
	err := row.Scan(&r.ID, &r.Source, &r.StartedAt, &finished, &r.OK,
		&r.ItemsFetched, &r.FindingsCreated, &runErr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: latest run: %w", err)
	}
	if finished.Valid {
		r.FinishedAt = &finished.Time
	}
	r.Error = runErr.String
	return &r, nil
}

func (s *Store) SourceEnabled(source string) (bool, error) {
	var enabled bool
	err := s.db.QueryRow(`SELECT enabled FROM source_state WHERE source = ?`, source).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil // no row => enabled by default
	}
	if err != nil {
		return false, fmt.Errorf("store: source enabled: %w", err)
	}
	return enabled, nil
}

func (s *Store) SetSourceEnabled(source string, enabled bool) error {
	_, err := s.db.Exec(
		`INSERT INTO source_state(source, enabled) VALUES(?,?)
		 ON CONFLICT(source) DO UPDATE SET enabled = excluded.enabled`,
		source, enabled)
	if err != nil {
		return fmt.Errorf("store: set source enabled: %w", err)
	}
	return nil
}

func (s *Store) DisabledSources() ([]string, error) {
	rows, err := s.db.Query(`SELECT source FROM source_state WHERE enabled = 0`)
	if err != nil {
		return nil, fmt.Errorf("store: disabled sources: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scan disabled source: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
