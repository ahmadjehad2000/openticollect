package collectors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// OTX collects subscribed pulses from AlienVault OTX.
type OTX struct {
	key        string
	baseURL    string
	windowDays int
}

func NewOTX(cfg *config.Config) *OTX {
	return &OTX{
		key:        cfg.OTXAPIKey,
		baseURL:    "https://otx.alienvault.com",
		windowDays: cfg.FetchWindowDays,
	}
}

func (o *OTX) Name() string            { return "otx" }
func (o *OTX) Interval() time.Duration { return 15 * time.Minute }

func (o *OTX) MissingEnv(cfg *config.Config) []string {
	if cfg.OTXAPIKey == "" {
		return []string{"OTX_API_KEY"}
	}
	return nil
}

func (o *OTX) Enabled(cfg *config.Config) bool { return len(o.MissingEnv(cfg)) == 0 }

type otxResponse struct {
	Results []otxPulse `json:"results"`
}

type otxPulse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Indicators  []struct {
		Indicator string `json:"indicator"`
	} `json:"indicators"`
}

func (o *OTX) Run(ctx context.Context, in Input) (Result, error) {
	q := url.Values{}
	q.Set("limit", "50")
	q.Set("modified_since", time.Now().Add(-fetchWindow(o.windowDays)).UTC().Format(time.RFC3339))
	endpoint := o.baseURL + "/api/v1/pulses/subscribed?" + q.Encode()

	var resp otxResponse
	if err := fetchJSON(ctx, in.HTTP, http.MethodGet, endpoint, nil,
		map[string]string{"X-OTX-API-KEY": o.key}, &resp); err != nil {
		return Result{}, fmt.Errorf("otx: %w", err)
	}

	m := matcher.New(in.Keywords)
	var res Result
	for _, p := range resp.Results {
		res.ItemsFetched++
		var sb strings.Builder
		sb.WriteString(p.Name + "\n" + p.Description)
		for _, ind := range p.Indicators {
			sb.WriteString("\n" + ind.Indicator)
		}
		sourceURL := o.baseURL + "/pulse/" + p.ID
		res.Findings = append(res.Findings, scanText("otx", sourceURL, sb.String(), "", m)...)
	}
	return res, nil
}
