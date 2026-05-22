package risk

import (
	"testing"
	"time"

	"openticollect/internal/ioc"
	"openticollect/internal/models"
)

func TestScoreBounds(t *testing.T) {
	now := time.Now()
	low := Score(Signals{Finding: models.Finding{Source: "nvd", Severity: "info",
		CreatedAt: now.Add(-60 * 24 * time.Hour)}, Now: now})
	if low < 0 || low > 100 {
		t.Fatalf("score out of bounds: %d", low)
	}
	high := Score(Signals{
		Finding:     models.Finding{Source: "darkweb", Severity: "critical", CreatedAt: now},
		Indicators:  make([]ioc.Indicator, 8),
		Credentials: 10,
		Now:         now,
	})
	if high != 100 {
		t.Fatalf("saturated score = %d, want 100", high)
	}
}

func TestScoreCredentialsDominate(t *testing.T) {
	now := time.Now()
	base := models.Finding{Source: "pastes", Severity: "warn", CreatedAt: now}
	noCreds := Score(Signals{Finding: base, Now: now})
	withCreds := Score(Signals{Finding: base, Credentials: 3, Now: now})
	if withCreds <= noCreds {
		t.Fatalf("credentials must raise the score: %d !> %d", withCreds, noCreds)
	}
}

func TestScoreRecencyDecays(t *testing.T) {
	now := time.Now()
	f := models.Finding{Source: "rssfeeds", Severity: "warn"}
	fresh := f
	fresh.CreatedAt = now
	old := f
	old.CreatedAt = now.Add(-40 * 24 * time.Hour)
	if Score(Signals{Finding: fresh, Now: now}) <= Score(Signals{Finding: old, Now: now}) {
		t.Fatalf("a fresh finding must outscore a 40-day-old one")
	}
}

func TestScoreCorrelationBonus(t *testing.T) {
	now := time.Now()
	f := models.Finding{Source: "correlation", Severity: "warn", CreatedAt: now}
	plain := models.Finding{Source: "rssfeeds", Severity: "warn", CreatedAt: now}
	if Score(Signals{Finding: f, Now: now}) <= Score(Signals{Finding: plain, Now: now}) {
		t.Fatalf("a correlation finding should carry a corroboration bonus")
	}
}

func TestBand(t *testing.T) {
	cases := map[int]string{0: "low", 39: "low", 40: "elevated", 69: "elevated", 70: "high", 100: "high"}
	for score, want := range cases {
		if got := Band(score); got != want {
			t.Errorf("Band(%d) = %q, want %q", score, got, want)
		}
	}
}
