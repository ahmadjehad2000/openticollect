package store

import (
	"testing"

	"openticollect/internal/models"
)

func sampleFinding(url, kw string) models.Finding {
	return models.Finding{
		Source:         "otx",
		SourceURL:      url,
		MatchedKeyword: kw,
		Severity:       "warn",
		Excerpt:        "context around " + kw,
		Raw:            `{"k":"v"}`,
		Hash:           models.HashFinding("otx", url, kw),
		Status:         "new",
	}
}

func TestInsertFindingsDedupes(t *testing.T) {
	s := newTestStore(t)
	f := sampleFinding("https://x/1", "acme.com")

	inserted, err := s.InsertFindings([]models.Finding{f, f}) // same hash twice
	if err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	if len(inserted) != 1 {
		t.Fatalf("expected 1 inserted, got %d", len(inserted))
	}
	if inserted[0].ID == 0 {
		t.Fatal("inserted finding must carry its new ID")
	}

	again, err := s.InsertFindings([]models.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("re-inserting same hash must yield 0, got %d", len(again))
	}
}

func TestListFindingsFilters(t *testing.T) {
	s := newTestStore(t)
	a := sampleFinding("https://x/1", "alpha")
	b := sampleFinding("https://x/2", "beta")
	b.Source = "nvd"
	if _, err := s.InsertFindings([]models.Finding{a, b}); err != nil {
		t.Fatal(err)
	}

	all, total, err := s.ListFindings(FindingFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 || len(all) != 2 {
		t.Fatalf("expected 2 findings, got len=%d total=%d", len(all), total)
	}

	onlyNVD, total, err := s.ListFindings(FindingFilter{Sources: []string{"nvd"}, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(onlyNVD) != 1 || onlyNVD[0].Source != "nvd" {
		t.Fatalf("source filter failed: len=%d total=%d", len(onlyNVD), total)
	}

	search, _, err := s.ListFindings(FindingFilter{Search: "alpha", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(search) != 1 || search[0].MatchedKeyword != "alpha" {
		t.Fatalf("search filter failed: %#v", search)
	}
}

func TestSetFindingStatusAndGet(t *testing.T) {
	s := newTestStore(t)
	inserted, _ := s.InsertFindings([]models.Finding{sampleFinding("https://x/9", "k")})
	id := inserted[0].ID

	if err := s.SetFindingStatus(id, "reviewed"); err != nil {
		t.Fatalf("SetFindingStatus: %v", err)
	}
	got, err := s.GetFinding(id)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got.Status != "reviewed" {
		t.Fatalf("status = %q, want reviewed", got.Status)
	}
}

func TestCountsForDashboard(t *testing.T) {
	s := newTestStore(t)
	s.InsertFindings([]models.Finding{
		sampleFinding("https://x/1", "a"),
		sampleFinding("https://x/2", "b"),
	})
	total, err := s.CountFindings()
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("CountFindings = %d, want 2", total)
	}
	last24, err := s.CountFindingsSince24h()
	if err != nil {
		t.Fatal(err)
	}
	if last24 != 2 {
		t.Fatalf("CountFindingsSince24h = %d, want 2", last24)
	}
}
