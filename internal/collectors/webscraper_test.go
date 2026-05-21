package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func acmeKeyword() []models.Keyword {
	return []models.Keyword{
		{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
	}
}

func TestWebscraperRunMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Write([]byte("User-agent: *\nAllow: /\n"))
		case "/page":
			w.Write([]byte(`<html><body><p>data leak involving acme.com today</p></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ws := NewWebscraper(&config.Config{WebscraperURLs: []string{srv.URL + "/page"}})
	ws.pause = 0
	in := Input{Keywords: acmeKeyword(), HTTP: srv.Client(), Logger: testLogger()}
	res, err := ws.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
}

func TestWebscraperFollowsLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusNotFound)
		case "/":
			w.Write([]byte(`<html><body><h1>index</h1><a href="/leak">details</a></body></html>`))
		case "/leak":
			w.Write([]byte(`<html><body><p>credentials for acme.com dumped here</p></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ws := NewWebscraper(&config.Config{WebscraperURLs: []string{srv.URL + "/"}})
	ws.pause = 0
	in := Input{Keywords: acmeKeyword(), HTTP: srv.Client(), Logger: testLogger()}
	res, err := ws.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsFetched < 2 {
		t.Fatalf("expected the scraper to follow the link (>=2 pages), got %d", res.ItemsFetched)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding on the linked page, got %d", len(res.Findings))
	}
	if res.Findings[0].SourceURL != srv.URL+"/leak" {
		t.Fatalf("finding should point at the linked page, got %q", res.Findings[0].SourceURL)
	}
}

func TestWebscraperMatchesLinkHref(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(`<html><body><a href="https://evil.acme.com/dump">click</a></body></html>`))
	}))
	defer srv.Close()

	ws := NewWebscraper(&config.Config{WebscraperURLs: []string{srv.URL + "/p"}})
	ws.pause = 0
	ws.maxDepth = 0 // don't follow; verify href-text matching on the seed
	in := Input{Keywords: acmeKeyword(), HTTP: srv.Client(), Logger: testLogger()}
	res, err := ws.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("a keyword inside a link target should match, got %d findings", len(res.Findings))
	}
}

func TestWebscraperRobotsDisallow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Write([]byte("User-agent: *\nDisallow: /\n"))
			return
		}
		w.Write([]byte(`<body>acme.com</body>`))
	}))
	defer srv.Close()

	ws := NewWebscraper(&config.Config{WebscraperURLs: []string{srv.URL + "/page"}})
	ws.pause = 0
	in := Input{Keywords: acmeKeyword(), HTTP: srv.Client(), Logger: testLogger()}
	res, err := ws.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatal("a robots.txt-disallowed page must not be scraped")
	}
}

func TestWebscraperMissingEnv(t *testing.T) {
	ws := NewWebscraper(&config.Config{})
	if ws.Enabled(&config.Config{}) {
		t.Fatal("webscraper with no URLs should be disabled")
	}
}
