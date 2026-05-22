package store

import (
	"testing"

	"openticollect/internal/models"
)

func TestAnalyticsAggregates(t *testing.T) {
	st := newTestStore(t)
	_, err := st.InsertFindings([]models.Finding{
		{Source: "pastes", MatchedKeyword: "acme", Severity: "warn", Excerpt: "x",
			Hash: models.HashFinding("pastes", "1", "acme")},
		{Source: "pastes", MatchedKeyword: "acme", Severity: "warn", Excerpt: "x",
			Hash: models.HashFinding("pastes", "2", "acme")},
		{Source: "darkweb", MatchedKeyword: "acme", Severity: "critical", Excerpt: "x",
			Hash: models.HashFinding("darkweb", "3", "acme")},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	bySource, err := st.FindingsBySource()
	if err != nil {
		t.Fatalf("FindingsBySource: %v", err)
	}
	counts := map[string]int{}
	for _, c := range bySource {
		counts[c.Label] = c.Count
	}
	if counts["pastes"] != 2 || counts["darkweb"] != 1 {
		t.Fatalf("FindingsBySource = %v, want pastes:2 darkweb:1", counts)
	}
	days, err := st.FindingsPerDay(30)
	if err != nil {
		t.Fatalf("FindingsPerDay: %v", err)
	}
	total := 0
	for _, d := range days {
		total += d.Count
	}
	if total != 3 {
		t.Fatalf("FindingsPerDay total = %d, want 3", total)
	}
}
