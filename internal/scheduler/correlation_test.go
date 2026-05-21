package scheduler

import (
	"context"
	"path/filepath"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/correlation"
	"openticollect/internal/models"
	"openticollect/internal/notifier"
	"openticollect/internal/store"
)

func corrStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "corr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestCorrelateRaisesSmartAlert(t *testing.T) {
	st := corrStore(t)
	// Same keyword from two distinct collector sources -> smart corroboration.
	if _, err := st.InsertFindings([]models.Finding{
		{Source: "rssfeeds", MatchedKeyword: "medicalcircles.com", Severity: "warn",
			Excerpt: "e", Hash: "h1", Status: "new"},
		{Source: "pastes", MatchedKeyword: "medicalcircles.com", Severity: "critical",
			Excerpt: "e", Hash: "h2", Status: "new"},
	}); err != nil {
		t.Fatal(err)
	}

	s := New(&config.Config{}, st, notifier.New(nil), nil,
		correlation.NewRunner(st), nil, nil, nil)
	s.correlate(context.Background())

	all, _, err := st.ListFindings(store.FindingFilter{
		Sources: []string{correlation.Source}, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 correlation finding, got %d", len(all))
	}
	if all[0].Severity != "critical" {
		t.Fatalf("correlated severity = %q, want critical (max contributing)", all[0].Severity)
	}
	if all[0].NotifiedAt == nil {
		t.Fatal("correlation finding should be dispatched and marked notified")
	}

	// A second pass the same day must not duplicate the alert.
	s.correlate(context.Background())
	all, _, _ = st.ListFindings(store.FindingFilter{
		Sources: []string{correlation.Source}, Limit: 50})
	if len(all) != 1 {
		t.Fatalf("correlation must dedup within a day, got %d", len(all))
	}
}

func TestCorrelateCustomRule(t *testing.T) {
	st := corrStore(t)
	// A custom rule: 1 source, 2 findings within 24h -> critical alert.
	if _, err := st.CreateCorrelationRule("watched domains", "acme.com", 1, 2, 1440, "critical"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertFindings([]models.Finding{
		{Source: "otx", MatchedKeyword: "acme.com", Severity: "info",
			Excerpt: "e", Hash: "a1", Status: "new"},
		{Source: "otx", MatchedKeyword: "acme.com", Severity: "info",
			Excerpt: "e", Hash: "a2", Status: "new"},
	}); err != nil {
		t.Fatal(err)
	}

	s := New(&config.Config{}, st, notifier.New(nil), nil,
		correlation.NewRunner(st), nil, nil, nil)
	s.correlate(context.Background())

	all, _, _ := st.ListFindings(store.FindingFilter{
		Sources: []string{correlation.Source}, Limit: 50})
	// Smart engine needs 2 sources or 5 findings — not met; only the custom rule fires.
	if len(all) != 1 {
		t.Fatalf("expected 1 correlation finding from the custom rule, got %d", len(all))
	}
	if all[0].Severity != "critical" {
		t.Fatalf("custom-rule severity = %q, want critical", all[0].Severity)
	}
}
