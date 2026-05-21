package collectors

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// Feodo collects the abuse.ch Feodo Tracker botnet C2 IP blocklist. Keyless
// clear-web source (the JSON download needs no Auth-Key).
type Feodo struct {
	url string
}

func NewFeodo(cfg *config.Config) *Feodo {
	return &Feodo{url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json"}
}

func (f *Feodo) Name() string                           { return "feodo" }
func (f *Feodo) Interval() time.Duration                { return 60 * time.Minute }
func (f *Feodo) MissingEnv(cfg *config.Config) []string { return nil }
func (f *Feodo) Enabled(cfg *config.Config) bool        { return true }

func (f *Feodo) Run(ctx context.Context, in Input) (Result, error) {
	var entries []struct {
		IP      string `json:"ip_address"`
		Port    int    `json:"port"`
		Malware string `json:"malware"`
		ASName  string `json:"as_name"`
		Country string `json:"country"`
	}
	if err := fetchJSON(ctx, in.HTTP, http.MethodGet, f.url, nil, nil, &entries); err != nil {
		return Result{}, fmt.Errorf("feodo: %w", err)
	}

	m := matcher.New(in.Keywords)
	var res Result
	for _, e := range entries {
		res.ItemsFetched++
		text := e.IP + " " + e.Malware + " " + e.ASName + " " + e.Country
		sourceURL := "https://feodotracker.abuse.ch/browse/host/" + e.IP + "/"
		res.Findings = append(res.Findings, scanText("feodo", sourceURL, text, "", m)...)
	}
	return res, nil
}
