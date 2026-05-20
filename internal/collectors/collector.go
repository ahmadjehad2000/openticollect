// Package collectors defines the Collector interface and the individual
// threat-intelligence source collectors.
package collectors

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/models"
	"openticollect/internal/version"
)

// Collector is one threat-intelligence source.
type Collector interface {
	Name() string                           // stable id, e.g. "rssfeeds"
	Enabled(cfg *config.Config) bool        // true when MissingEnv is empty
	MissingEnv(cfg *config.Config) []string // env vars needed but unset
	Interval() time.Duration                // base interval; scheduler adds +/-10% jitter
	Run(ctx context.Context, in Input) (Result, error)
}

// Input is passed to every collector run.
type Input struct {
	Keywords []models.Keyword
	HTTP     *http.Client
	Tor      *http.Client // nil if Tor disabled
	Logger   *slog.Logger
}

// Result is what a collector run produces.
type Result struct {
	ItemsFetched int
	Findings     []models.Finding
}

// uaTransport injects the openTIcollect User-Agent on every request.
type uaTransport struct{ rt http.RoundTripper }

func (t uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("User-Agent", version.String())
	return t.rt.RoundTrip(r2)
}

// DefaultHTTPClient is the shared client: 30s timeout, custom User-Agent.
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: uaTransport{rt: http.DefaultTransport},
	}
}

// All returns every collector, constructed against cfg.
func All(cfg *config.Config) []Collector {
	return []Collector{
		NewOTX(cfg),
		NewAbuseIPDB(cfg),
		NewAbuseCH(cfg),
		NewPulsedive(cfg),
		NewIntelX(cfg),
		NewHIBP(cfg),
		NewNVD(cfg),
		NewPastes(cfg),
		NewWebscraper(cfg),
		NewRSSFeeds(cfg),
		NewTelegram(cfg),
		NewDarkweb(cfg),
	}
}
