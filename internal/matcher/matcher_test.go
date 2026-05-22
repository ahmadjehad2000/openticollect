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

func TestLiteralMatchesWholeWordOnly(t *testing.T) {
	m := New([]models.Keyword{kw(1, "acme", "literal")})

	// "acme" appears as a fragment of a longer word — must NOT match.
	for _, text := range []string{
		"acmecorp had a breach",   // trailing letters
		"the blacme device leaked", // leading letters
		"acme2 is a different code", // trailing digit
		"99acme is unrelated",       // leading digit
	} {
		if hits := m.Match(text); len(hits) != 0 {
			t.Errorf("Match(%q) = %d hits, want 0 (keyword is only a word fragment)", text, len(hits))
		}
	}

	// "acme" appears as a whole word — must match exactly once.
	for _, text := range []string{
		"acme had a breach",
		"breach reported at acme.",
		"see (acme) in the dump",
		"ACME corp leaked data",
		"record format user:acme:secret",
		"acme",
	} {
		if hits := m.Match(text); len(hits) != 1 {
			t.Errorf("Match(%q) = %d hits, want 1 (keyword is a whole word)", text, len(hits))
		}
	}
}

func TestKeywordDoesNotConflictWithinAnother(t *testing.T) {
	// "book" must not fire on text that mentions the unrelated keyword
	// "facebook" — whole-word matching keeps the two from conflicting.
	m := New([]models.Keyword{kw(1, "book", "literal"), kw(2, "facebook", "literal")})
	hits := m.Match("the facebook account credentials were leaked")
	if len(hits) != 1 || hits[0].Keyword.ID != 2 {
		t.Fatalf("only the whole keyword 'facebook' should match, got %#v", hits)
	}

	// When "book" genuinely appears as its own word, it does match.
	if hits := m.Match("a book of leaked logins"); len(hits) != 1 || hits[0].Keyword.ID != 1 {
		t.Fatalf("'book' as a whole word should match, got %#v", hits)
	}
}

func TestDomainKeywordWholeWord(t *testing.T) {
	m := New([]models.Keyword{kw(1, "acme.com", "literal")})

	// The watched domain (and its subdomains) — must match.
	for _, text := range []string{
		"visit acme.com today",
		"login.acme.com is unreachable", // subdomain of the watched domain
		"go to acme.com/leak now",
	} {
		if hits := m.Match(text); len(hits) != 1 {
			t.Errorf("Match(%q) = %d hits, want 1", text, len(hits))
		}
	}

	// Different domains that merely share a prefix/suffix — must NOT match.
	for _, text := range []string{
		"acme.community has news",  // 'acme.com' followed by a letter
		"myacme.com is unrelated",  // 'acme.com' preceded by a letter
	} {
		if hits := m.Match(text); len(hits) != 0 {
			t.Errorf("Match(%q) = %d hits, want 0 (different domain)", text, len(hits))
		}
	}
}
