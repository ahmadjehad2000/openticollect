package collectors

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// AbuseIPDB collects the AbuseIPDB blacklist of high-confidence abusive IPs.
type AbuseIPDB struct {
	key     string
	baseURL string
}

func NewAbuseIPDB(cfg *config.Config) *AbuseIPDB {
	return &AbuseIPDB{key: cfg.AbuseIPDBKey, baseURL: "https://api.abuseipdb.com"}
}

func (a *AbuseIPDB) Name() string            { return "abuseipdb" }
func (a *AbuseIPDB) Interval() time.Duration { return 60 * time.Minute }

func (a *AbuseIPDB) MissingEnv(cfg *config.Config) []string {
	if cfg.AbuseIPDBKey == "" {
		return []string{"ABUSEIPDB_API_KEY"}
	}
	return nil
}

func (a *AbuseIPDB) Enabled(cfg *config.Config) bool { return len(a.MissingEnv(cfg)) == 0 }

type abuseIPDBResponse struct {
	Data []struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	} `json:"data"`
}

func (a *AbuseIPDB) Run(ctx context.Context, in Input) (Result, error) {
	endpoint := a.baseURL + "/api/v2/blacklist?confidenceMinimum=75&limit=1000"
	var resp abuseIPDBResponse
	if err := fetchJSON(ctx, in.HTTP, http.MethodGet, endpoint, nil,
		map[string]string{"Key": a.key, "Accept": "application/json"}, &resp); err != nil {
		return Result{}, fmt.Errorf("abuseipdb: %w", err)
	}

	m := matcher.New(in.Keywords)
	var res Result
	for _, e := range resp.Data {
		res.ItemsFetched++
		sourceURL := "https://www.abuseipdb.com/check/" + e.IPAddress
		res.Findings = append(res.Findings, scanText("abuseipdb", sourceURL, e.IPAddress, "", m)...)
	}
	return res, nil
}
