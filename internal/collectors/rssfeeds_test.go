package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

const sampleRSS = `<?xml version="1.0"?>
<rss version="2.0"><channel><title>Test Feed</title>
<item><title>Big breach</title><link>https://news/1</link>
<description>emails from acme.com were dumped</description></item>
<item><title>Unrelated</title><link>https://news/2</link>
<description>nothing of interest</description></item>
</channel></rss>`

func TestRSSFeedsRunMatchesKeyword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write([]byte(sampleRSS))
	}))
	defer srv.Close()

	cfg := &config.Config{RSSFeeds: []string{srv.URL}}
	rf := NewRSSFeeds(cfg)

	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "critical", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := rf.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", res.ItemsFetched)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].SourceURL != "https://news/1" {
		t.Errorf("finding SourceURL = %q", res.Findings[0].SourceURL)
	}
}

func TestRSSFeedsMissingEnv(t *testing.T) {
	rf := NewRSSFeeds(&config.Config{})
	if rf.Enabled(&config.Config{}) {
		t.Fatal("rssfeeds with no feeds should be disabled")
	}
	if got := rf.MissingEnv(&config.Config{}); len(got) != 1 || got[0] != "RSS_FEEDS" {
		t.Fatalf("MissingEnv = %#v", got)
	}
}
