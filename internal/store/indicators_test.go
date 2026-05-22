package store

import (
	"testing"

	"openticollect/internal/ioc"
	"openticollect/internal/models"
)

func TestInsertAndListIndicators(t *testing.T) {
	st := newTestStore(t)
	ins, err := st.InsertFindings([]models.Finding{{
		Source: "pastes", MatchedKeyword: "acme", Severity: "warn",
		Excerpt: "x", Hash: models.HashFinding("pastes", "u1", "acme"),
	}})
	if err != nil || len(ins) != 1 {
		t.Fatalf("seed finding: %v", err)
	}
	fid := ins[0].ID

	inds := []ioc.Indicator{
		{Kind: ioc.KindIPv4, Value: "203.0.113.7"},
		{Kind: ioc.KindDomain, Value: "evil.example.com"},
	}
	if err := st.InsertIndicators(fid, inds); err != nil {
		t.Fatalf("InsertIndicators: %v", err)
	}
	if err := st.InsertIndicators(fid, inds); err != nil {
		t.Fatalf("InsertIndicators (repeat): %v", err)
	}
	got, err := st.IndicatorsForFinding(fid)
	if err != nil {
		t.Fatalf("IndicatorsForFinding: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d indicators, want 2", len(got))
	}
	n, err := st.CountIndicators()
	if err != nil || n != 2 {
		t.Fatalf("CountIndicators = %d, %v; want 2", n, err)
	}
}

func TestIndicatorsByFindings(t *testing.T) {
	st := newTestStore(t)
	ins, _ := st.InsertFindings([]models.Finding{
		{Source: "a", MatchedKeyword: "k", Severity: "warn", Excerpt: "x",
			Hash: models.HashFinding("a", "u", "k")},
		{Source: "b", MatchedKeyword: "k", Severity: "warn", Excerpt: "x",
			Hash: models.HashFinding("b", "u", "k")},
	})
	_ = st.InsertIndicators(ins[0].ID, []ioc.Indicator{{Kind: ioc.KindCVE, Value: "cve-2024-3094"}})
	_ = st.InsertIndicators(ins[1].ID, []ioc.Indicator{{Kind: ioc.KindCVE, Value: "cve-2024-3094"}})
	m, err := st.IndicatorsByFindings([]int64{ins[0].ID, ins[1].ID})
	if err != nil {
		t.Fatalf("IndicatorsByFindings: %v", err)
	}
	if len(m[ins[0].ID]) != 1 || len(m[ins[1].ID]) != 1 {
		t.Fatalf("expected one indicator per finding, got %v", m)
	}
}

func TestListIndicatorsFilterByKind(t *testing.T) {
	st := newTestStore(t)
	ins, _ := st.InsertFindings([]models.Finding{{Source: "a", MatchedKeyword: "k",
		Severity: "warn", Excerpt: "x", Hash: models.HashFinding("a", "u", "k")}})
	_ = st.InsertIndicators(ins[0].ID, []ioc.Indicator{
		{Kind: ioc.KindIPv4, Value: "1.2.3.4"},
		{Kind: ioc.KindDomain, Value: "x.com"},
	})
	got, err := st.ListIndicators(IndicatorFilter{Kind: "ipv4", Limit: 50})
	if err != nil || len(got) != 1 || got[0].Value != "1.2.3.4" {
		t.Fatalf("ListIndicators(kind=ipv4) = %v, %v", got, err)
	}
}
