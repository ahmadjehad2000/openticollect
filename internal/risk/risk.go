// Package risk computes a deterministic 0–100 risk score for a finding.
//
// The score is intentionally explainable — every point traces to a concrete
// signal (severity, source trust, recency, extracted IOCs, leaked
// credentials, multi-source corroboration). There is no ML and no external
// AI: the project forbids both, and a transparent score is auditable.
package risk

import (
	"time"

	"openticollect/internal/ioc"
	"openticollect/internal/models"
)

// Signals are the inputs to a score. Indicators and Credentials come from the
// ioc package; Now is injected so scoring is testable and deterministic.
type Signals struct {
	Finding     models.Finding
	Indicators  []ioc.Indicator
	Credentials int // count of leaked credentials extracted from the finding
	Now         time.Time
}

// sourceTrust weights a collector by how strongly a hit there implies a real
// brand/leak exposure. Dark-web, paste and credential sources rank highest.
var sourceTrust = map[string]int{
	"darkweb":       15,
	"correlation":   15,
	"secretscanner": 14,
	"hibp":          13,
	"telegram":      13,
	"intelx":        12,
	"pastes":        12,
	"webscraper":    10,
	"abusech":       9,
	"feodo":         9,
	"otx":           9,
	"pulsedive":     9,
	"abuseipdb":     8,
	"cisakev":       7,
	"rssfeeds":      6,
	"nvd":           5,
}

func severityWeight(s string) int {
	switch s {
	case "critical":
		return 50
	case "warn":
		return 30
	default:
		return 10
	}
}

// recencyWeight linearly decays 0..10 over a 30-day window.
func recencyWeight(created, now time.Time) int {
	if created.IsZero() {
		return 0
	}
	days := now.Sub(created).Hours() / 24
	if days < 0 {
		days = 0
	}
	if days >= 30 {
		return 0
	}
	return int(10 * (1 - days/30))
}

func capInt(v, max int) int {
	if v > max {
		return max
	}
	return v
}

// Score returns the deterministic 0–100 risk score for s.
func Score(s Signals) int {
	score := severityWeight(s.Finding.Severity)
	score += sourceTrust[s.Finding.Source] // unknown source => 0
	score += recencyWeight(s.Finding.CreatedAt, s.Now)
	score += capInt(len(s.Indicators)*2, 12)
	score += capInt(s.Credentials*6, 24)
	if s.Finding.Source == "correlation" {
		score += 15 // already-corroborated signal
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

// Band maps a score to a UI severity band: low | elevated | high.
func Band(score int) string {
	switch {
	case score >= 70:
		return "high"
	case score >= 40:
		return "elevated"
	default:
		return "low"
	}
}
