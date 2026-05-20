package store

import (
	"fmt"
	"strings"

	"openticollect/internal/models"
)

func (s *Store) CreateKeyword(value, kind, severity string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("store: keyword value is empty")
	}
	if kind != "literal" && kind != "regex" {
		return 0, fmt.Errorf("store: invalid keyword kind %q", kind)
	}
	if !models.ValidSeverity(severity) {
		return 0, fmt.Errorf("store: invalid severity %q", severity)
	}
	res, err := s.db.Exec(
		`INSERT INTO keywords(value, kind, severity) VALUES(?,?,?)`,
		value, kind, severity)
	if err != nil {
		return 0, fmt.Errorf("store: create keyword: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) ListKeywords() ([]models.Keyword, error) {
	return s.queryKeywords(`SELECT id, value, kind, severity, enabled, created_at
		FROM keywords ORDER BY created_at DESC`)
}

func (s *Store) EnabledKeywords() ([]models.Keyword, error) {
	return s.queryKeywords(`SELECT id, value, kind, severity, enabled, created_at
		FROM keywords WHERE enabled = 1 ORDER BY created_at DESC`)
}

func (s *Store) queryKeywords(query string, args ...any) ([]models.Keyword, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query keywords: %w", err)
	}
	defer rows.Close()
	var out []models.Keyword
	for rows.Next() {
		var k models.Keyword
		if err := rows.Scan(&k.ID, &k.Value, &k.Kind, &k.Severity, &k.Enabled, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan keyword: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) SetKeywordEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE keywords SET enabled = ? WHERE id = ?`, enabled, id)
	if err != nil {
		return fmt.Errorf("store: set keyword enabled: %w", err)
	}
	return nil
}

func (s *Store) DeleteKeyword(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM keywords WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete keyword: %w", err)
	}
	return nil
}
