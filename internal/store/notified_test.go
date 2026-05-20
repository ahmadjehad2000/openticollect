package store

import (
	"testing"
	"time"

	"openticollect/internal/models"
)

func TestMarkNotified(t *testing.T) {
	s := newTestStore(t)
	inserted, _ := s.InsertFindings([]models.Finding{sampleFinding("https://x/1", "k")})
	id := inserted[0].ID

	if err := s.MarkNotified(id, time.Now()); err != nil {
		t.Fatalf("MarkNotified: %v", err)
	}
	got, err := s.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.NotifiedAt == nil {
		t.Fatal("NotifiedAt should be set after MarkNotified")
	}
}
