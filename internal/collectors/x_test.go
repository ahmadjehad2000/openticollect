package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

// nitterSearchPage mimics a Nitter search/timeline result page.
const nitterSearchPage = `<html><body>
<div class="timeline">
<div class="timeline-item">
  <a class="tweet-link" href="/leakbroker/status/1700000000000000001#m"></a>
  <div class="tweet-content">Selling a fresh database dump from acme.com — DM for a sample</div>
</div>
<div class="timeline-item">
  <a class="tweet-link" href="/randomuser/status/1700000000000000002#m"></a>
  <div class="tweet-content">just had coffee, lovely morning</div>
</div>
</div>
</body></html>`

func TestXRunFindsKeywordMentions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nitterSearchPage))
	}))
	defer srv.Close()

	x := NewX(&config.Config{XNitterInstances: []string{srv.URL}})
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "critical", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := x.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (only the acme.com tweet)", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Source != "x" {
		t.Errorf("Source = %q, want \"x\"", f.Source)
	}
	if f.MatchedKeyword != "acme.com" {
		t.Errorf("MatchedKeyword = %q, want acme.com", f.MatchedKeyword)
	}
	if f.SourceURL != "https://x.com/leakbroker/status/1700000000000000001" {
		t.Errorf("SourceURL = %q, want the canonical x.com permalink", f.SourceURL)
	}
}

func TestXFallsBackBetweenInstances(t *testing.T) {
	// The first instance is unreachable; the collector must fail over.
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nitterSearchPage))
	}))
	defer live.Close()

	x := NewX(&config.Config{XNitterInstances: []string{"http://127.0.0.1:1", live.URL}})
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   live.Client(),
		Logger: testLogger(),
	}
	res, err := x.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run should fail over to the live instance: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings from the live fallback instance")
	}
}

func TestXNoInstanceReachable(t *testing.T) {
	x := NewX(&config.Config{XNitterInstances: []string{"http://127.0.0.1:1"}})
	in := Input{
		Keywords: []models.Keyword{{ID: 1, Value: "acme", Kind: "literal", Enabled: true}},
		HTTP:     DefaultHTTPClient(),
		Logger:   testLogger(),
	}
	if _, err := x.Run(context.Background(), in); err == nil {
		t.Fatal("Run with no reachable instance should return an error")
	}
}

func TestXMisconfiguredWithoutInstance(t *testing.T) {
	if NewX(&config.Config{}).Enabled(&config.Config{}) {
		t.Fatal("x collector with no Nitter instance should be disabled")
	}
	cfg := &config.Config{XNitterInstances: []string{"https://nitter.example"}}
	if !NewX(cfg).Enabled(cfg) {
		t.Fatal("x collector with a configured instance should be enabled")
	}
}

func TestXHandleNormalization(t *testing.T) {
	cases := map[string]string{
		"@elonmusk":               "elonmusk",
		"x.com/elonmusk":          "elonmusk",
		"https://twitter.com/foo": "foo",
		"bar":                     "bar",
	}
	for in, want := range cases {
		if got := xHandle(in); got != want {
			t.Errorf("xHandle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestXPermalink(t *testing.T) {
	cases := map[string]string{
		"/leakbroker/status/123#m":  "https://x.com/leakbroker/status/123",
		"/user/status/9?cursor=abc": "https://x.com/user/status/9",
		"/":                         "",
		"":                          "",
	}
	for in, want := range cases {
		if got := xPermalink(in); got != want {
			t.Errorf("xPermalink(%q) = %q, want %q", in, got, want)
		}
	}
}
