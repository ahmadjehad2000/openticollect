package collectors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// Pulsedive collects recent high-risk indicators from the Pulsedive community
// API. Best-effort: an unexpected response shape yields zero items, not a failure.
type Pulsedive struct {
	key     string
	baseURL string
}

func NewPulsedive(cfg *config.Config) *Pulsedive {
	return &Pulsedive{key: cfg.PulsediveKey, baseURL: "https://pulsedive.com"}
}

func (p *Pulsedive) Name() string            { return "pulsedive" }
func (p *Pulsedive) Interval() time.Duration { return 30 * time.Minute }

func (p *Pulsedive) MissingEnv(cfg *config.Config) []string {
	if cfg.PulsediveKey == "" {
		return []string{"PULSEDIVE_API_KEY"}
	}
	return nil
}

func (p *Pulsedive) Enabled(cfg *config.Config) bool { return len(p.MissingEnv(cfg)) == 0 }

func (p *Pulsedive) Run(ctx context.Context, in Input) (Result, error) {
	q := url.Values{}
	q.Set("q", "risk=high")
	q.Set("limit", "100")
	q.Set("pretty", "0")
	q.Set("key", p.key)
	endpoint := p.baseURL + "/api/explore.php?" + q.Encode()

	var resp struct {
		Results []struct {
			Indicator string `json:"indicator"`
			Type      string `json:"type"`
			Risk      string `json:"risk"`
		} `json:"results"`
	}
	if err := fetchJSON(ctx, in.HTTP, http.MethodGet, endpoint, nil, nil, &resp); err != nil {
		return Result{}, fmt.Errorf("pulsedive: %w", err)
	}

	m := matcher.New(in.Keywords)
	var res Result
	for _, r := range resp.Results {
		res.ItemsFetched++
		text := r.Indicator + " " + r.Type + " " + r.Risk
		sourceURL := p.baseURL + "/indicator/?q=" + url.QueryEscape(r.Indicator)
		res.Findings = append(res.Findings, scanText("pulsedive", sourceURL, text, "", m)...)
	}
	return res, nil
}
