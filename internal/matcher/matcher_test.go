package matcher

import (
	"strings"
	"testing"

	"openticollect/internal/models"
)

func kw(id int64, value, kind string) models.Keyword {
	return models.Keyword{ID: id, Value: value, Kind: kind, Severity: "warn", Enabled: true}
}

func TestLiteralMatchCaseInsensitive(t *testing.T) {
	m := New([]models.Keyword{kw(1, "Acme.com", "literal")})
	hits := m.Match("leak found at ACME.COM today")
	if len(hits) != 1 || hits[0].Keyword.ID != 1 {
		t.Fatalf("expected 1 literal hit, got %#v", hits)
	}
}

func TestRegexMatch(t *testing.T) {
	m := New([]models.Keyword{kw(2, `[a-z]+@acme\.com`, "regex")})
	hits := m.Match("contact bob@acme.com please")
	if len(hits) != 1 {
		t.Fatalf("expected 1 regex hit, got %#v", hits)
	}
}

func TestNoMatch(t *testing.T) {
	m := New([]models.Keyword{kw(1, "acme", "literal")})
	if hits := m.Match("nothing relevant here"); len(hits) != 0 {
		t.Fatalf("expected 0 hits, got %#v", hits)
	}
}

func TestDisabledKeywordIgnored(t *testing.T) {
	k := kw(1, "acme", "literal")
	k.Enabled = false
	m := New([]models.Keyword{k})
	if hits := m.Match("acme acme acme"); len(hits) != 0 {
		t.Fatal("disabled keyword must not match")
	}
}

func TestBadRegexSkippedNotFatal(t *testing.T) {
	m := New([]models.Keyword{
		kw(1, "(unclosed", "regex"),
		kw(2, "acme", "literal"),
	})
	hits := m.Match("acme is here")
	if len(hits) != 1 || hits[0].Keyword.ID != 2 {
		t.Fatalf("bad regex must be skipped, literal must still match: %#v", hits)
	}
}

func TestExcerptWindowAndCap(t *testing.T) {
	long := strings.Repeat("x", 5000) + "acme" + strings.Repeat("y", 5000)
	ex := Excerpt(long, strings.Index(long, "acme"), len("acme"))
	if !strings.Contains(ex, "acme") {
		t.Fatal("excerpt must contain the match")
	}
	if len(ex) > 2048 {
		t.Fatalf("excerpt length = %d, must be <= 2048", len(ex))
	}
}
