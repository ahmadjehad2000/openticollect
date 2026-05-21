package scheduler

import (
	"testing"

	"openticollect/internal/models"
)

func TestEnrichExtractsAndScores(t *testing.T) {
	st := corrStore(t)
	ins, err := st.InsertFindings([]models.Finding{{
		Source: "pastes", SourceURL: "http://paste.example/x",
		MatchedKeyword: "acme", Severity: "critical",
		Excerpt: "leak: admin@acme.com:Sup3rSecret! from 203.0.113.9",
		Hash:    models.HashFinding("pastes", "http://paste.example/x", "acme"),
	}})
	if err != nil || len(ins) != 1 {
		t.Fatalf("seed: %v", err)
	}
	enrichFindings(st, ins)

	got, err := st.IndicatorsForFinding(ins[0].ID)
	if err != nil {
		t.Fatalf("IndicatorsForFinding: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected extracted indicators (ip + email)")
	}
	f, err := st.GetFinding(ins[0].ID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if f.RiskScore <= 0 {
		t.Fatalf("expected a positive risk score, got %d", f.RiskScore)
	}
}
