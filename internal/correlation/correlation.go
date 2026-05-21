// Package correlation turns a window of raw findings into higher-confidence
// correlated alerts. Two engines run together: a built-in smart engine (default,
// no configuration) and a custom engine driven by user-defined rules.
package correlation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"openticollect/internal/models"
)

// Source label for findings produced by correlation; excluded from re-correlation.
const Source = "correlation"

const (
	smartWindow    = 24 * time.Hour
	burstThreshold = 5
)

// Alert is a correlated signal ready to be turned into a finding.
type Alert struct {
	Engine   string // "smart" | "custom"
	Rule     string // heuristic name or custom rule name
	Keyword  string
	Severity string
	Summary  string
}

// RuleStore supplies the enabled custom correlation rules.
type RuleStore interface {
	EnabledCorrelationRules() ([]models.CorrelationRule, error)
}

// Runner evaluates the smart engine plus every enabled custom rule.
type Runner struct {
	rules RuleStore
}

func NewRunner(rules RuleStore) *Runner { return &Runner{rules: rules} }

// Correlate evaluates recent findings (which must already exclude correlation
// findings) and returns the alerts produced by both engines.
func (r *Runner) Correlate(recent []models.Finding, now time.Time) ([]Alert, error) {
	alerts := smartCorrelate(recent, now)
	rules, err := r.rules.EnabledCorrelationRules()
	if err != nil {
		return alerts, fmt.Errorf("correlation: load rules: %w", err)
	}
	for _, rule := range rules {
		alerts = append(alerts, customCorrelate(rule, recent, now)...)
	}
	return alerts, nil
}

// group is the per-keyword aggregate within a window.
type group struct {
	keyword string
	sources map[string]bool
	count   int
	maxSev  int
}

// groupByKeyword aggregates findings created at/after cutoff, keyed by keyword.
// If keyword is non-empty, only that keyword is considered.
func groupByKeyword(findings []models.Finding, cutoff time.Time, keyword string) map[string]*group {
	groups := map[string]*group{}
	for _, f := range findings {
		if f.Source == Source {
			continue // never correlate correlation output
		}
		if !f.CreatedAt.IsZero() && f.CreatedAt.Before(cutoff) {
			continue
		}
		if keyword != "" && f.MatchedKeyword != keyword {
			continue
		}
		g := groups[f.MatchedKeyword]
		if g == nil {
			g = &group{keyword: f.MatchedKeyword, sources: map[string]bool{}}
			groups[f.MatchedKeyword] = g
		}
		g.sources[f.Source] = true
		g.count++
		if rank := models.SeverityRank(f.Severity); rank > g.maxSev {
			g.maxSev = rank
		}
	}
	return groups
}

func sevName(rank int) string {
	switch rank {
	case 2:
		return "critical"
	case 1:
		return "warn"
	default:
		return "info"
	}
}

// plural renders a count with a correctly pluralized noun.
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func sortedSources(g *group) []string {
	out := make([]string, 0, len(g.sources))
	for s := range g.sources {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// smartCorrelate applies the built-in heuristics: multi-source corroboration
// (a keyword seen across >= 2 distinct sources) and activity bursts.
func smartCorrelate(findings []models.Finding, now time.Time) []Alert {
	groups := groupByKeyword(findings, now.Add(-smartWindow), "")
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var alerts []Alert
	for _, k := range keys {
		g := groups[k]
		multiSource := len(g.sources) >= 2
		burst := g.count >= burstThreshold
		if !multiSource && !burst {
			continue
		}
		var reasons []string
		if multiSource {
			reasons = append(reasons, fmt.Sprintf("corroborated by %s (%s)",
				plural(len(g.sources), "source"), strings.Join(sortedSources(g), ", ")))
		}
		if burst {
			reasons = append(reasons, fmt.Sprintf("%s indicate an activity burst",
				plural(g.count, "finding")))
		}
		alerts = append(alerts, Alert{
			Engine:   "smart",
			Rule:     "smart-correlation",
			Keyword:  g.keyword,
			Severity: sevName(g.maxSev),
			Summary: fmt.Sprintf("Smart correlation — %q %s within 24h.",
				g.keyword, strings.Join(reasons, "; ")),
		})
	}
	return alerts
}

// customCorrelate evaluates one user rule over the findings.
func customCorrelate(rule models.CorrelationRule, findings []models.Finding, now time.Time) []Alert {
	window := time.Duration(rule.WindowMinutes) * time.Minute
	groups := groupByKeyword(findings, now.Add(-window), rule.Keyword)
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var alerts []Alert
	for _, k := range keys {
		g := groups[k]
		if len(g.sources) < rule.MinSources || g.count < rule.MinCount {
			continue
		}
		alerts = append(alerts, Alert{
			Engine:   "custom",
			Rule:     rule.Name,
			Keyword:  g.keyword,
			Severity: rule.Severity,
			Summary: fmt.Sprintf("Rule %q matched — %q seen in %s across %s (%s) within %dm.",
				rule.Name, g.keyword, plural(g.count, "finding"),
				plural(len(g.sources), "source"),
				strings.Join(sortedSources(g), ", "), rule.WindowMinutes),
		})
	}
	return alerts
}

// AlertToFinding converts a correlated alert into a Finding. The dedup hash
// includes the engine, rule, keyword and calendar day, so a given correlation
// fires at most once per day rather than on every scheduler cycle.
func AlertToFinding(a Alert, now time.Time) models.Finding {
	day := now.UTC().Format("2006-01-02")
	dedup := strings.Join([]string{a.Engine, a.Rule, a.Keyword, day}, "|")
	return models.Finding{
		Source:         Source,
		MatchedKeyword: a.Keyword,
		Severity:       a.Severity,
		Excerpt:        a.Summary,
		Hash:           models.HashFinding(Source, dedup, a.Keyword),
		Status:         "new",
	}
}
