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

func TestMatchHomoglyph(t *testing.T) {
	m := New([]models.Keyword{
		{Value: "acme", Kind: "literal", Severity: "warn", Enabled: true},
	})
	// "аcme" — leading char is a Cyrillic 'а', not Latin 'a'.
	hits := m.Match("breach at аcme corp")
	if len(hits) != 1 {
		t.Fatalf("homoglyph text should match the literal keyword, got %d hits", len(hits))
	}
}

func TestMatchFullWidth(t *testing.T) {
	m := New([]models.Keyword{
		{Value: "acme", Kind: "literal", Severity: "warn", Enabled: true},
	})
	// Full-width Latin "ａｃｍｅ" (U+FF41 U+FF43 U+FF4D U+FF45).
	if hits := m.Match("ａｃｍｅ leaked"); len(hits) != 1 {
		t.Fatalf("full-width text should match, got %d hits", len(hits))
	}
}

func TestMatchExcerptOffsetAfterFold(t *testing.T) {
	m := New([]models.Keyword{
		{Value: "acme", Kind: "literal", Severity: "warn", Enabled: true},
	})
	// Multi-byte runes precede the match; the reported Index must point into
	// the ORIGINAL text so the excerpt is coherent.
	text := "ррр acme dump" // three Cyrillic 'р' then " acme dump"
	hits := m.Match(text)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	got := Excerpt(text, hits[0].Index, len("acme"))
	if !matcherContains(got, "acme dump") {
		t.Fatalf("excerpt %q should contain the original match context", got)
	}
}

func matcherContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
