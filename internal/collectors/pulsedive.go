package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

// Pulsedive looks up each indicator-shaped watchlist keyword (domain, IP or URL)
// against Pulsedive's indicator API. This is the free-tier-appropriate endpoint:
// the explore/search API is rate-limited far more aggressively.
type Pulsedive struct {
	key     string
	baseURL string
	pause   time.Duration // delay between lookups, respecting per-second limits
}

func NewPulsedive(cfg *config.Config) *Pulsedive {
	return &Pulsedive{
		key:     cfg.PulsediveKey,
		baseURL: "https://pulsedive.com",
		pause:   1500 * time.Millisecond,
	}
}

func (p *Pulsedive) Name() string            { return "pulsedive" }
func (p *Pulsedive) Interval() time.Duration { return 60 * time.Minute }

func (p *Pulsedive) MissingEnv(cfg *config.Config) []string {
	if cfg.PulsediveKey == "" {
		return []string{"PULSEDIVE_API_KEY"}
	}
	return nil
}

func (p *Pulsedive) Enabled(cfg *config.Config) bool { return len(p.MissingEnv(cfg)) == 0 }

// indicatorRe loosely matches domains and URLs; IPs are matched separately.
var indicatorRe = regexp.MustCompile(`^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$`)

// looksLikeIndicator reports whether a keyword is worth a Pulsedive lookup.
func looksLikeIndicator(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " \t") {
		return false
	}
	if net.ParseIP(v) != nil {
		return true
	}
	return indicatorRe.MatchString(v)
}

type pulsediveIndicator struct {
	IID       int    `json:"iid"`
	Indicator string `json:"indicator"`
	Type      string `json:"type"`
	Risk      string `json:"risk"`
}

func (p *Pulsedive) Run(ctx context.Context, in Input) (Result, error) {
	var res Result
	attempted, succeeded, rateLimited := 0, 0, false

	for _, kw := range in.Keywords {
		if !kw.Enabled || !looksLikeIndicator(kw.Value) {
			continue
		}
		if attempted > 0 {
			pacePause(ctx, p.pause)
		}
		attempted++

		ind, status, err := p.lookup(ctx, in.HTTP, kw.Value)
		switch {
		case status == http.StatusTooManyRequests:
			in.Logger.Warn("pulsedive: rate limited (HTTP 429), pausing until next cycle",
				"indicator", kw.Value)
			rateLimited = true
		case status == http.StatusNotFound:
			succeeded++
			res.ItemsFetched++
			continue
		case err != nil:
			in.Logger.Warn("pulsedive: lookup failed", "indicator", kw.Value, "err", err)
			continue
		default:
			succeeded++
			res.ItemsFetched++
			if pulsediveRisky(ind.Risk) {
				res.Findings = append(res.Findings, models.Finding{
					Source: "pulsedive",
					SourceURL: p.baseURL + "/indicator/?iid=" +
						strconv.Itoa(ind.IID),
					MatchedKeyword: kw.Value,
					Severity:       kw.Severity,
					Excerpt: fmt.Sprintf("Pulsedive rates %q as a %s-risk %s indicator.",
						ind.Indicator, ind.Risk, ind.Type),
					Hash:   models.HashFinding("pulsedive", "iid:"+strconv.Itoa(ind.IID), kw.Value),
					Status: "new",
				})
			}
			continue
		}
		if rateLimited {
			break // stop hammering a throttled key; resume next cycle
		}
	}

	if rateLimited && succeeded == 0 {
		return res, fmt.Errorf("pulsedive: rate limited (HTTP 429) — the free tier " +
			"caps requests per second/day/month; see https://pulsedive.com/account")
	}
	return res, nil
}

// lookup queries one indicator. It returns the HTTP status so the caller can
// distinguish 404 (not a known indicator) and 429 (rate limited) from errors.
func (p *Pulsedive) lookup(ctx context.Context, client *http.Client, value string) (pulsediveIndicator, int, error) {
	q := url.Values{}
	q.Set("indicator", value)
	if p.key != "" {
		q.Set("key", p.key)
	}
	endpoint := p.baseURL + "/api/indicator.php?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return pulsediveIndicator{}, 0, fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return pulsediveIndicator{}, 0, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return pulsediveIndicator{}, resp.StatusCode, nil
	}
	var ind pulsediveIndicator
	if err := json.NewDecoder(resp.Body).Decode(&ind); err != nil {
		return pulsediveIndicator{}, resp.StatusCode, fmt.Errorf("decode: %w", err)
	}
	return ind, resp.StatusCode, nil
}

// pulsediveRisky reports whether a Pulsedive risk level is worth alerting on.
func pulsediveRisky(risk string) bool {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "medium", "high", "critical":
		return true
	default:
		return false
	}
}
