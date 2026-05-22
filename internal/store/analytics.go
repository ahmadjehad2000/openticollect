package store

import "fmt"

// Count is a generic labelled aggregate row used by the analytics page.
type Count struct {
	Label string
	Count int
}

// FindingsBySource returns the finding count per collector, busiest first.
func (s *Store) FindingsBySource() ([]Count, error) {
	rows, err := s.db.Query(
		`SELECT source, count(*) FROM findings GROUP BY source ORDER BY count(*) DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: findings by source: %w", err)
	}
	defer rows.Close()
	return scanCounts(rows)
}

// FindingsPerDay returns the finding count per calendar day over the last
// `days` days, oldest first.
func (s *Store) FindingsPerDay(days int) ([]Count, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	rows, err := s.db.Query(
		`SELECT date(created_at) AS d, count(*)
		 FROM findings
		 WHERE created_at >= datetime('now', ?)
		 GROUP BY d ORDER BY d ASC`, fmt.Sprintf("-%d days", days))
	if err != nil {
		return nil, fmt.Errorf("store: findings per day: %w", err)
	}
	defer rows.Close()
	return scanCounts(rows)
}

// IndicatorsByKind returns the extracted-indicator count per kind.
func (s *Store) IndicatorsByKind() ([]Count, error) {
	rows, err := s.db.Query(
		`SELECT kind, count(*) FROM indicators GROUP BY kind ORDER BY count(*) DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: indicators by kind: %w", err)
	}
	defer rows.Close()
	return scanCounts(rows)
}

func scanCounts(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]Count, error) {
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Label, &c.Count); err != nil {
			return nil, fmt.Errorf("store: scan count: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
