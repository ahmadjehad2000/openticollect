package store

import (
	"testing"
	"time"

	"openticollect/internal/models"
)

func TestCorrelationRuleCRUD(t *testing.T) {
	s := newTestStore(t)

	id, err := s.CreateCorrelationRule("multi-feed domains", "acme.com", 2, 3, 120, "critical")
	if err != nil {
		t.Fatalf("CreateCorrelationRule: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	all, err := s.ListCorrelationRules()
	if err != nil {
		t.Fatalf("ListCorrelationRules: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(all))
	}
	r := all[0]
	if r.Name != "multi-feed domains" || r.Keyword != "acme.com" ||
		r.MinSources != 2 || r.MinCount != 3 || r.WindowMinutes != 120 ||
		r.Severity != "critical" || !r.Enabled {
		t.Fatalf("rule fields wrong: %#v", r)
	}

	if err := s.SetCorrelationRuleEnabled(id, false); err != nil {
		t.Fatalf("SetCorrelationRuleEnabled: %v", err)
	}
	en, _ := s.EnabledCorrelationRules()
	if len(en) != 0 {
		t.Fatalf("expected 0 enabled rules, got %d", len(en))
	}

	if err := s.DeleteCorrelationRule(id); err != nil {
		t.Fatalf("DeleteCorrelationRule: %v", err)
	}
	all, _ = s.ListCorrelationRules()
	if len(all) != 0 {
		t.Fatalf("expected 0 rules after delete, got %d", len(all))
	}
}

func TestCreateCorrelationRuleValidates(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateCorrelationRule("", "", 2, 1, 60, "warn"); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if _, err := s.CreateCorrelationRule("r", "", 2, 1, 60, "loud"); err == nil {
		t.Fatal("bad severity must be rejected")
	}
	if _, err := s.CreateCorrelationRule("r", "", 0, 2, 60, "warn"); err == nil {
		t.Fatal("min_sources < 1 must be rejected")
	}
	if _, err := s.CreateCorrelationRule("r", "", 1, 1, 60, "warn"); err == nil {
		t.Fatal("min_count < 2 must be rejected (a single finding is not a correlation)")
	}
}

func TestFindingsSince(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.InsertFindings([]models.Finding{
		sampleFinding("https://x/1", "a"),
		sampleFinding("https://x/2", "b"),
	}); err != nil {
		t.Fatal(err)
	}
	recent, err := s.FindingsSince(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("FindingsSince: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("expected 2 findings in the last hour, got %d", len(recent))
	}
	none, err := s.FindingsSince(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 findings in the future window, got %d", len(none))
	}
}
