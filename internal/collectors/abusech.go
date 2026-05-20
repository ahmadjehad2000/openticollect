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

// AbuseCH collects recent IOCs from abuse.ch URLhaus, ThreatFox and MalwareBazaar,
// all authenticated with a single Auth-Key.
type AbuseCH struct {
	key          string
	urlhausURL   string
	threatfoxURL string
	bazaarURL    string
}

func NewAbuseCH(cfg *config.Config) *AbuseCH {
	return &AbuseCH{
		key:          cfg.AbuseCHKey,
		urlhausURL:   "https://urlhaus-api.abuse.ch/v1/urls/recent/",
		threatfoxURL: "https://threatfox-api.abuse.ch/api/v1/",
		bazaarURL:    "https://mb-api.abuse.ch/api/v1/",
	}
}

func (a *AbuseCH) Name() string            { return "abusech" }
func (a *AbuseCH) Interval() time.Duration { return 15 * time.Minute }

func (a *AbuseCH) MissingEnv(cfg *config.Config) []string {
	if cfg.AbuseCHKey == "" {
		return []string{"ABUSECH_AUTH_KEY"}
	}
	return nil
}

func (a *AbuseCH) Enabled(cfg *config.Config) bool { return len(a.MissingEnv(cfg)) == 0 }

type abusechItem struct {
	url  string
	text string
}

func (a *AbuseCH) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result
	ok := 0

	for _, src := range []struct {
		name  string
		fetch func(context.Context, *http.Client) ([]abusechItem, error)
	}{
		{"urlhaus", a.urlhaus},
		{"threatfox", a.threatfox},
		{"malwarebazaar", a.bazaar},
	} {
		items, err := src.fetch(ctx, in.HTTP)
		if err != nil {
			in.Logger.Warn("abusech: endpoint failed", "endpoint", src.name, "err", err)
			continue
		}
		ok++
		for _, it := range items {
			res.ItemsFetched++
			res.Findings = append(res.Findings, scanText("abusech", it.url, it.text, "", m)...)
		}
	}
	if ok == 0 {
		return res, fmt.Errorf("abusech: all three endpoints failed")
	}
	return res, nil
}

func (a *AbuseCH) urlhaus(ctx context.Context, client *http.Client) ([]abusechItem, error) {
	var r struct {
		URLs []struct {
			URL    string `json:"url"`
			Threat string `json:"threat"`
		} `json:"urls"`
	}
	form := url.Values{"limit": {"100"}}
	if err := fetchJSON(ctx, client, http.MethodPost, a.urlhausURL,
		strings.NewReader(form.Encode()), a.formHeaders(), &r); err != nil {
		return nil, err
	}
	var items []abusechItem
	for _, u := range r.URLs {
		items = append(items, abusechItem{url: u.URL, text: u.URL + " " + u.Threat})
	}
	return items, nil
}

func (a *AbuseCH) threatfox(ctx context.Context, client *http.Client) ([]abusechItem, error) {
	var r struct {
		Data []struct {
			IOC        string `json:"ioc"`
			Malware    string `json:"malware"`
			ThreatType string `json:"threat_type"`
		} `json:"data"`
	}
	if err := fetchJSON(ctx, client, http.MethodPost, a.threatfoxURL,
		strings.NewReader(`{"query":"get_iocs","days":1}`),
		map[string]string{"Auth-Key": a.key, "Content-Type": "application/json"}, &r); err != nil {
		return nil, err
	}
	var items []abusechItem
	for _, d := range r.Data {
		items = append(items, abusechItem{
			url:  "https://threatfox.abuse.ch/browse.php?search=ioc%3A" + url.QueryEscape(d.IOC),
			text: d.IOC + " " + d.Malware + " " + d.ThreatType,
		})
	}
	return items, nil
}

func (a *AbuseCH) bazaar(ctx context.Context, client *http.Client) ([]abusechItem, error) {
	var r struct {
		Data []struct {
			SHA256    string `json:"sha256_hash"`
			FileName  string `json:"file_name"`
			Signature string `json:"signature"`
		} `json:"data"`
	}
	form := url.Values{"query": {"get_recent"}, "selector": {"time"}}
	if err := fetchJSON(ctx, client, http.MethodPost, a.bazaarURL,
		strings.NewReader(form.Encode()), a.formHeaders(), &r); err != nil {
		return nil, err
	}
	var items []abusechItem
	for _, d := range r.Data {
		items = append(items, abusechItem{
			url:  "https://bazaar.abuse.ch/sample/" + d.SHA256 + "/",
			text: d.SHA256 + " " + d.FileName + " " + d.Signature,
		})
	}
	return items, nil
}

func (a *AbuseCH) formHeaders() map[string]string {
	return map[string]string{
		"Auth-Key":     a.key,
		"Content-Type": "application/x-www-form-urlencoded",
	}
}
