package correlation

import (
	"strings"
	"testing"
	"time"

	"openticollect/internal/models"
)

func finding(source, keyword, severity string, age time.Duration) models.Finding {
	return models.Finding{
		Source:         source,
		MatchedKeyword: keyword,
		Severity:       severity,
		CreatedAt:      time.Now().Add(-age),
	}
}

// staticRules is a RuleStore backed by a fixed slice.
type staticRules []models.CorrelationRule

func (s staticRules) EnabledCorrelationRules() ([]models.CorrelationRule, error) {
	return []models.CorrelationRule(s), nil
}

func TestSmartMultiSourceCorroboration(t *testing.T) {
	now := time.Now()
	findings := []models.Finding{
		finding("rssfeeds", "acme.com", "warn", time.Hour),
		finding("pastes", "acme.com", "warn", 2*time.Hour),
		finding("rssfeeds", "lonely.com", "warn", time.Hour), // single source
	}
	alerts := smartCorrelate(findings, now)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 smart alert, got %d: %#v", len(alerts), alerts)
	}
	if alerts[0].Keyword != "acme.com" || alerts[0].Engine != "smart" {
		t.Fatalf("wrong alert: %#v", alerts[0])
	}
	if !strings.Contains(alerts[0].Summary, "2 sources") {
		t.Fatalf("summary missing source count: %q", alerts[0].Summary)
	}
}

func TestSmartSeverityIsMaxContributing(t *testing.T) {
	now := time.Now()
	findings := []models.Finding{
		finding("rssfeeds", "acme.com", "info", time.Hour),
		finding("pastes", "acme.com", "critical", time.Hour),
	}
	alerts := smartCorrelate(findings, now)
	if len(alerts) != 1 || alerts[0].Severity != "critical" {
		t.Fatalf("expected critical severity from corroboration, got %#v", alerts)
	}
}

func TestSmartBurstDetection(t *testing.T) {
	now := time.Now()
	var findings []models.Finding
	for i := 0; i < 6; i++ {
		findings = append(findings, finding("pastes", "leak", "warn", time.Hour))
	}
	alerts := smartCorrelate(findings, now)
	if len(alerts) != 1 || !strings.Contains(alerts[0].Summary, "burst") {
		t.Fatalf("expected a burst alert, got %#v", alerts)
	}
}

func TestSmartIgnoresOldAndCorrelationFindings(t *testing.T) {
	now := time.Now()
	findings := []models.Finding{
		finding("rssfeeds", "acme.com", "warn", time.Hour),
		finding("pastes", "acme.com", "warn", 48*time.Hour), // outside 24h window
		finding(Source, "acme.com", "warn", time.Hour),      // correlation output
	}
	if alerts := smartCorrelate(findings, now); len(alerts) != 0 {
		t.Fatalf("stale + correlation findings must not corroborate: %#v", alerts)
	}
}

func TestCustomRuleMatches(t *testing.T) {
	now := time.Now()
	rule := models.CorrelationRule{
		Name: "watched domains", Keyword: "acme.com",
		MinSources: 2, MinCount: 3, WindowMinutes: 180, Severity: "critical",
	}
	findings := []models.Finding{
		finding("rssfeeds", "acme.com", "info", 30*time.Minute),
		finding("pastes", "acme.com", "info", time.Hour),
		finding("otx", "acme.com", "info", 2*time.Hour),
	}
	alerts := customCorrelate(rule, findings, now)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 custom alert, got %d", len(alerts))
	}
	if alerts[0].Severity != "critical" || alerts[0].Rule != "watched domains" {
		t.Fatalf("custom alert wrong: %#v", alerts[0])
	}
}

func TestCustomRuleBelowThreshold(t *testing.T) {
	now := time.Now()
	rule := models.CorrelationRule{
		Name: "r", Keyword: "acme.com",
		MinSources: 3, MinCount: 1, WindowMinutes: 180, Severity: "warn",
	}
	findings := []models.Finding{
		finding("rssfeeds", "acme.com", "info", time.Hour),
		finding("pastes", "acme.com", "info", time.Hour),
	}
	if alerts := customCorrelate(rule, findings, now); len(alerts) != 0 {
		t.Fatalf("2 sources must not satisfy a min_sources=3 rule: %#v", alerts)
	}
}

func TestCustomRuleWindowExcludesOld(t *testing.T) {
	now := time.Now()
	rule := models.CorrelationRule{
		Name: "r", Keyword: "acme.com",
		MinSources: 2, MinCount: 2, WindowMinutes: 60, Severity: "warn",
	}
	findings := []models.Finding{
		finding("rssfeeds", "acme.com", "info", 10*time.Minute),
		finding("pastes", "acme.com", "info", 5*time.Hour), // outside 60m window
	}
	if alerts := customCorrelate(rule, findings, now); len(alerts) != 0 {
		t.Fatalf("a finding outside the rule window must not count: %#v", alerts)
	}
}

func TestRunnerCombinesEngines(t *testing.T) {
	now := time.Now()
	findings := []models.Finding{
		finding("rssfeeds", "acme.com", "warn", time.Hour),
		finding("pastes", "acme.com", "warn", time.Hour),
	}
	rules := staticRules{{
		Name: "domains", Keyword: "acme.com",
		MinSources: 2, MinCount: 2, WindowMinutes: 1440, Severity: "critical",
	}}
	alerts, err := NewRunner(rules).Correlate(findings, now)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	// smart (multi-source) + custom rule = 2 alerts.
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts (smart + custom), got %d: %#v", len(alerts), alerts)
	}
}

func TestAlertToFindingDedupPerDay(t *testing.T) {
	a := Alert{Engine: "smart", Rule: "smart-correlation", Keyword: "acme.com", Severity: "warn", Summary: "x"}
	day := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	f1 := AlertToFinding(a, day)
	f2 := AlertToFinding(a, day.Add(3*time.Hour))  // same day
	f3 := AlertToFinding(a, day.Add(24*time.Hour)) // next day
	if f1.Hash != f2.Hash {
		t.Fatal("same alert same day must share a hash (dedups)")
	}
	if f1.Hash == f3.Hash {
		t.Fatal("a new day must produce a fresh hash (re-alerts)")
	}
	if f1.Source != Source {
		t.Fatalf("correlation finding source = %q, want %q", f1.Source, Source)
	}
}
