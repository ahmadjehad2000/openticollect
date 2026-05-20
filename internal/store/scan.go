package store

import (
	"database/sql"
	"fmt"

	"openticollect/internal/models"
)

// errNoRows lets callers detect "not found" without importing database/sql.
var errNoRows = sql.ErrNoRows

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanFinding(r rowScanner) (models.Finding, error) {
	var (
		f         models.Finding
		sourceURL sql.NullString
		raw       sql.NullString
		notified  sql.NullTime
	)
	err := r.Scan(&f.ID, &f.Source, &sourceURL, &f.MatchedKeyword, &f.Severity,
		&f.Excerpt, &raw, &f.Hash, &f.Status, &notified, &f.CreatedAt)
	if err != nil {
		return models.Finding{}, fmt.Errorf("store: scan finding: %w", err)
	}
	f.SourceURL = sourceURL.String
	f.Raw = raw.String
	if notified.Valid {
		f.NotifiedAt = &notified.Time
	}
	return f, nil
}
