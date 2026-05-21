package store

import (
	"database/sql"
	"fmt"
	"strings"

	"openticollect/internal/ioc"
	"openticollect/internal/models"
)

// IndicatorFilter describes a /api/indicators query. Zero values mean no filter.
type IndicatorFilter struct {
	Kind   string
	Value  string
	Limit  int
	Offset int
}

// InsertIndicators stores the extracted indicators for one finding. It is
// idempotent: the UNIQUE(finding_id,kind,value) index drops repeats.
func (s *Store) InsertIndicators(findingID int64, inds []ioc.Indicator) error {
	for _, in := range inds {
		if in.Value == "" {
			continue
		}
		_, err := s.db.Exec(
			`INSERT OR IGNORE INTO indicators(finding_id, kind, value) VALUES(?,?,?)`,
			findingID, string(in.Kind), clip(in.Value, 512))
		if err != nil {
			return fmt.Errorf("store: insert indicator: %w", err)
		}
	}
	return nil
}

// IndicatorsForFinding returns all indicators associated with a single finding,
// ordered by kind and value.
func (s *Store) IndicatorsForFinding(findingID int64) ([]models.Indicator, error) {
	rows, err := s.db.Query(
		`SELECT id, finding_id, kind, value, created_at
		 FROM indicators WHERE finding_id = ? ORDER BY kind, value`, findingID)
	if err != nil {
		return nil, fmt.Errorf("store: indicators for finding: %w", err)
	}
	defer rows.Close()
	return scanIndicators(rows)
}

// IndicatorsByFindings batch-loads indicators for many findings in one query,
// keyed by finding ID — used by the IOC correlation pass.
func (s *Store) IndicatorsByFindings(ids []int64) (map[int64][]models.Indicator, error) {
	out := map[int64][]models.Indicator{}
	if len(ids) == 0 {
		return out, nil
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	rows, err := s.db.Query(
		`SELECT id, finding_id, kind, value, created_at
		 FROM indicators WHERE finding_id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: indicators by findings: %w", err)
	}
	defer rows.Close()
	all, err := scanIndicators(rows)
	if err != nil {
		return nil, err
	}
	for _, in := range all {
		out[in.FindingID] = append(out[in.FindingID], in)
	}
	return out, nil
}

// ListIndicators returns indicators matching the given filter, paginated.
func (s *Store) ListIndicators(f IndicatorFilter) ([]models.Indicator, error) {
	var where []string
	var args []any
	if f.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.Value != "" {
		where = append(where, "value LIKE ?")
		args = append(args, "%"+f.Value+"%")
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args = append(args, limit, f.Offset)
	rows, err := s.db.Query(
		`SELECT id, finding_id, kind, value, created_at
		 FROM indicators`+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list indicators: %w", err)
	}
	defer rows.Close()
	return scanIndicators(rows)
}

// CountIndicators returns the total number of stored indicators.
func (s *Store) CountIndicators() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM indicators`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count indicators: %w", err)
	}
	return n, nil
}

// scanIndicators consumes an indicators result set.
func scanIndicators(rows *sql.Rows) ([]models.Indicator, error) {
	var out []models.Indicator
	for rows.Next() {
		var in models.Indicator
		if err := rows.Scan(&in.ID, &in.FindingID, &in.Kind, &in.Value, &in.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan indicator: %w", err)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}
