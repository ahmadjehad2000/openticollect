package store

import (
	"fmt"
	"strings"
	"time"

	"openticollect/internal/models"
)

// FindingsSince returns every finding created at or after t, newest first.
// The cutoff is formatted to match SQLite's CURRENT_TIMESTAMP text format so the
// comparison is a like-for-like string compare.
func (s *Store) FindingsSince(t time.Time) ([]models.Finding, error) {
	cutoff := t.UTC().Format("2006-01-02 15:04:05")
	rows, err := s.db.Query(
		`SELECT id, source, source_url, matched_keyword, severity, excerpt, raw,
		        hash, status, notified_at, created_at
		 FROM findings WHERE created_at >= ? ORDER BY created_at DESC`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("store: findings since: %w", err)
	}
	defer rows.Close()
	var out []models.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) CreateCorrelationRule(name, keyword string,
	minSources, minCount, windowMinutes int, severity string) (int64, error) {
	name = strings.TrimSpace(name)
	keyword = strings.TrimSpace(keyword)
	if name == "" {
		return 0, fmt.Errorf("store: correlation rule name is empty")
	}
	if !models.ValidSeverity(severity) {
		return 0, fmt.Errorf("store: invalid severity %q", severity)
	}
	if minSources < 1 || minCount < 1 || windowMinutes < 1 {
		return 0, fmt.Errorf("store: correlation rule thresholds must be >= 1")
	}
	res, err := s.db.Exec(
		`INSERT INTO correlation_rules
		 (name, keyword, min_sources, min_count, window_minutes, severity)
		 VALUES(?,?,?,?,?,?)`,
		name, keyword, minSources, minCount, windowMinutes, severity)
	if err != nil {
		return 0, fmt.Errorf("store: create correlation rule: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) ListCorrelationRules() ([]models.CorrelationRule, error) {
	return s.queryCorrelationRules(`SELECT id, name, keyword, min_sources, min_count,
		window_minutes, severity, enabled, created_at
		FROM correlation_rules ORDER BY created_at DESC`)
}

func (s *Store) EnabledCorrelationRules() ([]models.CorrelationRule, error) {
	return s.queryCorrelationRules(`SELECT id, name, keyword, min_sources, min_count,
		window_minutes, severity, enabled, created_at
		FROM correlation_rules WHERE enabled = 1 ORDER BY created_at DESC`)
}

func (s *Store) queryCorrelationRules(query string, args ...any) ([]models.CorrelationRule, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query correlation rules: %w", err)
	}
	defer rows.Close()
	var out []models.CorrelationRule
	for rows.Next() {
		var r models.CorrelationRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Keyword, &r.MinSources, &r.MinCount,
			&r.WindowMinutes, &r.Severity, &r.Enabled, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan correlation rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SetCorrelationRuleEnabled(id int64, enabled bool) error {
	if _, err := s.db.Exec(
		`UPDATE correlation_rules SET enabled = ? WHERE id = ?`, enabled, id); err != nil {
		return fmt.Errorf("store: set correlation rule enabled: %w", err)
	}
	return nil
}

func (s *Store) DeleteCorrelationRule(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM correlation_rules WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete correlation rule: %w", err)
	}
	return nil
}
