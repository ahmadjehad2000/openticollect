package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func pulsediveInput(srv *httptest.Server) Input {
	return Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "medicalcircles.com", Kind: "literal", Severity: "critical", Enabled: true},
			{ID: 2, Value: "breach", Kind: "literal", Severity: "warn", Enabled: true}, // not indicator-shaped
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
}

func TestPulsediveLooksUpIndicators(t *testing.T) {
	var lookups int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/indicator.php" {
			t.Errorf("unexpected path %q (explore endpoint must not be used)", r.URL.Path)
		}
		lookups++
		if r.URL.Query().Get("indicator") != "medicalcircles.com" {
			t.Errorf("unexpected indicator %q", r.URL.Query().Get("indicator"))
		}
		w.Write([]byte(`{"iid":42,"indicator":"medicalcircles.com","type":"domain","risk":"high"}`))
	}))
	defer srv.Close()

	p := NewPulsedive(&config.Config{PulsediveKey: "k"})
	p.baseURL, p.pause = srv.URL, 0
	res, err := p.Run(context.Background(), pulsediveInput(srv))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if lookups != 1 {
		t.Fatalf("expected exactly 1 lookup (only the indicator-shaped keyword), got %d", lookups)
	}
	if len(res.Findings) != 1 || res.Findings[0].MatchedKeyword != "medicalcircles.com" {
		t.Fatalf("findings = %#v", res.Findings)
	}
}

func TestPulsediveNotFoundIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := NewPulsedive(&config.Config{PulsediveKey: "k"})
	p.baseURL, p.pause = srv.URL, 0
	res, err := p.Run(context.Background(), pulsediveInput(srv))
	if err != nil {
		t.Fatalf("a 404 (unknown indicator) must not fail the run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
}

func TestPulsediveRateLimitedReportsClearly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p := NewPulsedive(&config.Config{PulsediveKey: "k"})
	p.baseURL, p.pause = srv.URL, 0
	_, err := p.Run(context.Background(), pulsediveInput(srv))
	if err == nil {
		t.Fatal("a fully rate-limited run should report an error")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("error should clearly mention rate limiting, got: %v", err)
	}
}

func TestPulsediveMissingEnv(t *testing.T) {
	p := NewPulsedive(&config.Config{})
	if p.Enabled(&config.Config{}) {
		t.Fatal("pulsedive with no key should be disabled")
	}
}

func TestLooksLikeIndicator(t *testing.T) {
	yes := []string{"medicalcircles.com", "https://evil.example/x", "8.8.8.8", "sub.domain.co.uk"}
	no := []string{"breach", "medical circles", "medicalcircles", ""}
	for _, v := range yes {
		if !looksLikeIndicator(v) {
			t.Errorf("looksLikeIndicator(%q) = false, want true", v)
		}
	}
	for _, v := range no {
		if looksLikeIndicator(v) {
			t.Errorf("looksLikeIndicator(%q) = true, want false", v)
		}
	}
}
