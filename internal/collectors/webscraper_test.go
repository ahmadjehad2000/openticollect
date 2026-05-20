package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

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
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := ws.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
}

func TestWebscraperRobotsDisallow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Write([]byte("User-agent: *\nDisallow: /\n"))
		default:
			w.Write([]byte(`<body>acme.com</body>`))
		}
	}))
	defer srv.Close()

	ws := NewWebscraper(&config.Config{WebscraperURLs: []string{srv.URL + "/page"}})
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
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
