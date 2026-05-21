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

// NVD collects recently modified CVEs from the NVD CVE API 2.0 and matches them
// against the watchlist (e.g. watched product names).
type NVD struct {
	key        string
	baseURL    string
	windowDays int
}

func NewNVD(cfg *config.Config) *NVD {
	return &NVD{
		key:        cfg.NVDAPIKey,
		baseURL:    "https://services.nvd.nist.gov",
		windowDays: cfg.FetchWindowDays,
	}
}

func (n *NVD) Name() string                           { return "nvd" }
func (n *NVD) Interval() time.Duration                { return 30 * time.Minute }
func (n *NVD) MissingEnv(cfg *config.Config) []string { return nil } // keyless; key is optional
func (n *NVD) Enabled(cfg *config.Config) bool        { return true }

func (n *NVD) Run(ctx context.Context, in Input) (Result, error) {
	const nvdTime = "2006-01-02T15:04:05.000"
	now := time.Now().UTC()
	// The NVD API caps a lastModStartDate/EndDate range at 120 days.
	window := fetchWindow(n.windowDays)
	if maxWindow := 120 * 24 * time.Hour; window > maxWindow {
		window = maxWindow
	}
	q := url.Values{}
	q.Set("lastModStartDate", now.Add(-window).Format(nvdTime))
	q.Set("lastModEndDate", now.Format(nvdTime))
	endpoint := n.baseURL + "/rest/json/cves/2.0?" + q.Encode()

	headers := map[string]string{}
	if n.key != "" {
		headers["apiKey"] = n.key
	}

	var resp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := fetchJSON(ctx, in.HTTP, http.MethodGet, endpoint, nil, headers, &resp); err != nil {
		return Result{}, fmt.Errorf("nvd: %w", err)
	}

	m := matcher.New(in.Keywords)
	var res Result
	for _, v := range resp.Vulnerabilities {
		res.ItemsFetched++
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		text := v.CVE.ID + "\n" + desc
		sourceURL := "https://nvd.nist.gov/vuln/detail/" + v.CVE.ID
		res.Findings = append(res.Findings, scanText("nvd", sourceURL, text, "", m)...)
	}
	return res, nil
}
