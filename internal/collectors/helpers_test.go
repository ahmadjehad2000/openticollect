package collectors

import (
	"testing"

	"openticollect/internal/matcher"
	"openticollect/internal/models"
)

func TestScanTextBuildsFindings(t *testing.T) {
	kw := models.Keyword{ID: 1, Value: "acme.com", Kind: "literal", Severity: "critical", Enabled: true}
	m := matcher.New([]models.Keyword{kw})

	findings := scanText("rssfeeds", "https://x/1", "breach at acme.com today", `{"raw":1}`, m)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Source != "rssfeeds" || f.SourceURL != "https://x/1" {
		t.Errorf("source fields wrong: %#v", f)
	}
	if f.MatchedKeyword != "acme.com" || f.Severity != "critical" {
		t.Errorf("keyword fields wrong: %#v", f)
	}
	if f.Hash != models.HashFinding("rssfeeds", "https://x/1", "acme.com") {
		t.Errorf("hash wrong: %q", f.Hash)
	}
	if f.Status != "new" || f.Raw != `{"raw":1}` {
		t.Errorf("status/raw wrong: %#v", f)
	}
}

func TestScanTextNoMatch(t *testing.T) {
	m := matcher.New([]models.Keyword{
		{ID: 1, Value: "acme", Kind: "literal", Severity: "warn", Enabled: true},
	})
	if got := scanText("s", "u", "nothing here", "", m); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestDefaultHTTPClientSetsUserAgent(t *testing.T) {
	c := DefaultHTTPClient()
	if c.Timeout == 0 {
		t.Fatal("DefaultHTTPClient must set a timeout")
	}
}
