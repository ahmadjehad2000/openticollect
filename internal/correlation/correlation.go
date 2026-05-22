// Package correlation turns a window of raw findings into higher-confidence
// correlated alerts. Two engines run together: a built-in smart engine (default,
// no configuration) and a custom engine driven by user-defined rules.
//
// Every alert is evidence-backed: it names the contributing collector sources
// and carries a representative source URL, so a correlated finding always
// points at the raw findings that produced it.
package correlation

import (
	"encoding/json"
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

// EvidenceItem ties a correlated alert back to one contributing collector.
type EvidenceItem struct {
	Source string `json:"source"`
	URL    string `json:"url"`
}

// Alert is a correlated signal ready to be turned into a finding.
type Alert struct {
	Engine     string // "smart" | "custom"
	Rule       string // heuristic name or custom rule name
	Keyword    string
	Severity   string
	Summary    string
	Evidence   []EvidenceItem
	PrimaryURL string // representative URL of a contributing finding
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
// findings) and returns the alerts produced by all engines. iocs maps a
// finding ID to the indicators extracted from it; pass nil to skip IOC
// correlation.
func (r *Runner) Correlate(recent []models.Finding,
	iocs map[int64][]models.Indicator, now time.Time) ([]Alert, error) {
	alerts := smartCorrelate(recent, now)
	alerts = append(alerts, iocCorrelate(recent, iocs, now)...)
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
	urls    map[string]string // source -> first non-empty source_url seen
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
			g = &group{keyword: f.MatchedKeyword, sources: map[string]bool{}, urls: map[string]string{}}
			groups[f.MatchedKeyword] = g
		}
		g.sources[f.Source] = true
		if f.SourceURL != "" && g.urls[f.Source] == "" {
			g.urls[f.Source] = f.SourceURL
		}
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

// evidence builds the per-source evidence list and a representative URL.
func evidence(g *group) ([]EvidenceItem, string) {
	items := make([]EvidenceItem, 0, len(g.sources))
	primary := ""
	for _, s := range sortedSources(g) {
		u := g.urls[s]
		items = append(items, EvidenceItem{Source: s, URL: u})
		if primary == "" && u != "" {
			primary = u
		}
	}
	return items, primary
}

// evidenceText renders the evidence list for an alert summary.
func evidenceText(items []EvidenceItem) string {
	parts := make([]string, 0, len(items))
	for _, e := range items {
		if e.URL != "" {
			parts = append(parts, e.Source+": "+e.URL)
		} else {
			parts = append(parts, e.Source+" (no URL reported)")
		}
	}
	return strings.Join(parts, " · ")
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
			reasons = append(reasons, "corroborated by "+plural(len(g.sources), "source"))
		}
		if burst {
			reasons = append(reasons, plural(g.count, "finding")+" indicate an activity burst")
		}
		ev, primary := evidence(g)
		alerts = append(alerts, Alert{
			Engine:   "smart",
			Rule:     "smart-correlation",
			Keyword:  g.keyword,
			Severity: sevName(g.maxSev),
			Summary: fmt.Sprintf("Smart correlation: %q %s within 24h. Evidence — %s",
				g.keyword, strings.Join(reasons, "; "), evidenceText(ev)),
			Evidence:   ev,
			PrimaryURL: primary,
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
		ev, primary := evidence(g)
		alerts = append(alerts, Alert{
			Engine:   "custom",
			Rule:     rule.Name,
			Keyword:  g.keyword,
			Severity: rule.Severity,
			Summary: fmt.Sprintf("Rule %q: %q seen in %s across %s within %dm. Evidence — %s",
				rule.Name, g.keyword, plural(g.count, "finding"),
				plural(len(g.sources), "source"), rule.WindowMinutes, evidenceText(ev)),
			Evidence:   ev,
			PrimaryURL: primary,
		})
	}
	return alerts
}

// AlertToFinding converts a correlated alert into a Finding. The dedup hash
// includes the engine, rule, keyword and calendar day, so a given correlation
// fires at most once per day rather than on every scheduler cycle. SourceURL is
// a representative contributing URL and Raw carries the full evidence list.
func AlertToFinding(a Alert, now time.Time) models.Finding {
	day := now.UTC().Format("2006-01-02")
	dedup := strings.Join([]string{a.Engine, a.Rule, a.Keyword, day}, "|")
	raw, _ := json.Marshal(map[string]any{
		"engine":   a.Engine,
		"rule":     a.Rule,
		"keyword":  a.Keyword,
		"evidence": a.Evidence,
	})
	return models.Finding{
		Source:         Source,
		SourceURL:      a.PrimaryURL,
		MatchedKeyword: a.Keyword,
		Severity:       a.Severity,
		Excerpt:        a.Summary,
		Raw:            string(raw),
		Hash:           models.HashFinding(Source, dedup, a.Keyword),
		Status:         "new",
	}
}
