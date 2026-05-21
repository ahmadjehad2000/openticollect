package store

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"openticollect/internal/models"
)

// FindingFilter describes a /findings query. Zero values mean "no filter".
type FindingFilter struct {
	Sources  []string
	Severity string
	Search   string   // matches matched_keyword or excerpt
	Statuses []string // status IN (...)
	MinRisk  int      // findings with risk_score >= MinRisk; 0 = no filter
	Sort     string   // "risk" => ORDER BY risk_score DESC; default => created_at DESC
	Limit    int
	Offset   int
}

// InsertFindings inserts each finding with INSERT OR IGNORE on the hash unique
// index. It returns only the findings that were newly inserted, each with its ID.
func (s *Store) InsertFindings(findings []models.Finding) ([]models.Finding, error) {
	var inserted []models.Finding
	for _, f := range findings {
		f.Excerpt = clip(f.Excerpt, 2048)
		f.Raw = clip(f.Raw, 16384)
		if f.Status == "" {
			f.Status = "new"
		}
		res, err := s.db.Exec(
			`INSERT OR IGNORE INTO findings
			 (source, source_url, matched_keyword, severity, excerpt, raw, hash, status)
			 VALUES(?,?,?,?,?,?,?,?)`,
			f.Source, f.SourceURL, f.MatchedKeyword, f.Severity,
			f.Excerpt, f.Raw, f.Hash, f.Status)
		if err != nil {
			return inserted, fmt.Errorf("store: insert finding: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // duplicate hash
		}
		f.ID, _ = res.LastInsertId()
		inserted = append(inserted, f)
	}
	return inserted, nil
}

func (s *Store) ListFindings(f FindingFilter) ([]models.Finding, int, error) {
	var where []string
	var args []any

	if len(f.Sources) > 0 {
		ph := make([]string, len(f.Sources))
		for i, src := range f.Sources {
			ph[i] = "?"
			args = append(args, src)
		}
		where = append(where, "source IN ("+strings.Join(ph, ",")+")")
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.Search != "" {
		where = append(where, "(matched_keyword LIKE ? OR excerpt LIKE ?)")
		like := "%" + f.Search + "%"
		args = append(args, like, like)
	}
	if len(f.Statuses) > 0 {
		ph := make([]string, len(f.Statuses))
		for i, st := range f.Statuses {
			ph[i] = "?"
			args = append(args, st)
		}
		where = append(where, "status IN ("+strings.Join(ph, ",")+")")
	}
	if f.MinRisk > 0 {
		where = append(where, "risk_score >= ?")
		args = append(args, f.MinRisk)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM findings`+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: count findings: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	pageArgs := append(append([]any{}, args...), limit, f.Offset)
	order := "created_at DESC"
	if f.Sort == "risk" {
		order = "risk_score DESC, created_at DESC"
	}
	rows, err := s.db.Query(
		`SELECT id, source, source_url, matched_keyword, severity, excerpt, raw,
		        hash, status, notified_at, created_at, risk_score
		 FROM findings`+clause+` ORDER BY `+order+` LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list findings: %w", err)
	}
	defer rows.Close()

	var out []models.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

func (s *Store) GetFinding(id int64) (models.Finding, error) {
	row := s.db.QueryRow(
		`SELECT id, source, source_url, matched_keyword, severity, excerpt, raw,
		        hash, status, notified_at, created_at, risk_score FROM findings WHERE id = ?`, id)
	f, err := scanFinding(row)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return models.Finding{}, fmt.Errorf("store: finding %d not found", id)
		}
		return models.Finding{}, err
	}
	return f, nil
}

func (s *Store) SetFindingStatus(id int64, status string) error {
	if status != "new" && status != "reviewed" && status != "suppressed" {
		return fmt.Errorf("store: invalid finding status %q", status)
	}
	if _, err := s.db.Exec(`UPDATE findings SET status = ? WHERE id = ?`, status, id); err != nil {
		return fmt.Errorf("store: set finding status: %w", err)
	}
	return nil
}

// SetFindingRisk stores a computed risk score for a finding.
func (s *Store) SetFindingRisk(id int64, score int) error {
	if _, err := s.db.Exec(`UPDATE findings SET risk_score = ? WHERE id = ?`, score, id); err != nil {
		return fmt.Errorf("store: set finding risk: %w", err)
	}
	return nil
}

func (s *Store) CountFindings() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM findings`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count findings: %w", err)
	}
	return n, nil
}

func (s *Store) CountFindingsSince24h() (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT count(*) FROM findings WHERE created_at >= datetime('now','-1 day')`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count findings 24h: %w", err)
	}
	return n, nil
}

// MarkNotified records that a finding has been dispatched to notifiers.
func (s *Store) MarkNotified(id int64, at time.Time) error {
	if _, err := s.db.Exec(`UPDATE findings SET notified_at = ? WHERE id = ?`, at, id); err != nil {
		return fmt.Errorf("store: mark notified: %w", err)
	}
	return nil
}

// clip truncates s to at most max bytes.
func clip(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
