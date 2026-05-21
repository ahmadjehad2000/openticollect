package collectors

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// CISAKEV collects the CISA Known Exploited Vulnerabilities catalog — CVEs
// confirmed to be exploited in the wild. Keyless clear-web source.
type CISAKEV struct {
	url string
}

func NewCISAKEV(cfg *config.Config) *CISAKEV {
	return &CISAKEV{
		url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
	}
}

func (c *CISAKEV) Name() string                           { return "cisakev" }
func (c *CISAKEV) Interval() time.Duration                { return 6 * time.Hour }
func (c *CISAKEV) MissingEnv(cfg *config.Config) []string { return nil }
func (c *CISAKEV) Enabled(cfg *config.Config) bool        { return true }

func (c *CISAKEV) Run(ctx context.Context, in Input) (Result, error) {
	var resp struct {
		Vulnerabilities []struct {
			CveID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			ShortDescription  string `json:"shortDescription"`
		} `json:"vulnerabilities"`
	}
	if err := fetchJSON(ctx, in.HTTP, http.MethodGet, c.url, nil, nil, &resp); err != nil {
		return Result{}, fmt.Errorf("cisakev: %w", err)
	}

	m := matcher.New(in.Keywords)
	var res Result
	for _, v := range resp.Vulnerabilities {
		res.ItemsFetched++
		text := v.CveID + "\n" + v.VendorProject + " " + v.Product + "\n" +
			v.VulnerabilityName + "\n" + v.ShortDescription
		sourceURL := "https://nvd.nist.gov/vuln/detail/" + v.CveID
		res.Findings = append(res.Findings, scanText("cisakev", sourceURL, text, "", m)...)
	}
	return res, nil
}
