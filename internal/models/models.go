// Package models holds the plain data types shared across openTIcollect.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Keyword struct {
	ID        int64
	Value     string
	Kind      string // "literal" | "regex"
	Severity  string // "info" | "warn" | "critical"
	Enabled   bool
	CreatedAt time.Time
}

type Finding struct {
	ID             int64
	Source         string
	SourceURL      string
	MatchedKeyword string
	Severity       string
	Excerpt        string
	Raw            string // JSON text, may be empty
	Hash           string
	Status         string // "new" | "reviewed" | "suppressed"
	NotifiedAt     *time.Time
	CreatedAt      time.Time
}

type Run struct {
	ID              int64
	Source          string
	StartedAt       time.Time
	FinishedAt      *time.Time
	OK              bool
	ItemsFetched    int
	FindingsCreated int
	Error           string
}

// SourceStatus is a view model assembled by the server from scheduler + store data.
type SourceStatus struct {
	Name       string
	Status     string // "enabled" | "disabled" | "misconfigured"
	LastRun    *time.Time
	NextRun    *time.Time
	LastError  string
	MissingEnv []string
}

// SeverityRank orders severities for notifier gating. Unknown => 0.
func SeverityRank(s string) int {
	switch s {
	case "warn":
		return 1
	case "critical":
		return 2
	default:
		return 0
	}
}

func ValidSeverity(s string) bool {
	return s == "info" || s == "warn" || s == "critical"
}

// HashFinding is the dedupe key: sha256(source + source_url + matched_keyword).
func HashFinding(source, sourceURL, keyword string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + sourceURL + "\x00" + keyword))
	return hex.EncodeToString(sum[:])
}
