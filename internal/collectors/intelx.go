package collectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

// IntelX searches the IntelX free tier for each enabled keyword. Every returned
// record counts as a hit for that keyword.
type IntelX struct {
	key     string
	baseURL string
}

func NewIntelX(cfg *config.Config) *IntelX {
	return &IntelX{key: cfg.IntelXKey, baseURL: "https://free.intelx.io"}
}

func (i *IntelX) Name() string            { return "intelx" }
func (i *IntelX) Interval() time.Duration { return 30 * time.Minute }

func (i *IntelX) MissingEnv(cfg *config.Config) []string {
	if cfg.IntelXKey == "" {
		return []string{"INTELX_API_KEY"}
	}
	return nil
}

func (i *IntelX) Enabled(cfg *config.Config) bool { return len(i.MissingEnv(cfg)) == 0 }

type intelxRecord struct {
	SystemID string `json:"systemid"`
	Name     string `json:"name"`
	Bucket   string `json:"bucket"`
}

func (i *IntelX) Run(ctx context.Context, in Input) (Result, error) {
	var res Result
	enabled, searched := 0, 0
	for _, kw := range in.Keywords {
		if !kw.Enabled {
			continue
		}
		enabled++
		recs, err := i.search(ctx, in.HTTP, kw.Value)
		if err != nil {
			in.Logger.Warn("intelx: search failed", "term", kw.Value, "err", err)
			continue
		}
		searched++
		for _, rec := range recs {
			res.ItemsFetched++
			res.Findings = append(res.Findings, models.Finding{
				Source:         "intelx",
				SourceURL:      i.baseURL + "/file/view?f=" + url.QueryEscape(rec.SystemID),
				MatchedKeyword: kw.Value,
				Severity:       kw.Severity,
				Excerpt:        rec.Name + " (" + rec.Bucket + ")",
				Hash:           models.HashFinding("intelx", rec.SystemID, kw.Value),
				Status:         "new",
			})
		}
	}
	if enabled > 0 && searched == 0 {
		return res, fmt.Errorf("intelx: all searches failed")
	}
	return res, nil
}

func (i *IntelX) search(ctx context.Context, client *http.Client, term string) ([]intelxRecord, error) {
	body, _ := json.Marshal(map[string]any{
		"term": term, "maxresults": 10, "media": 0, "target": 0, "timeout": 5,
	})
	var sr struct {
		ID string `json:"id"`
	}
	if err := fetchJSON(ctx, client, http.MethodPost, i.baseURL+"/intelligent/search",
		bytes.NewReader(body),
		map[string]string{"x-key": i.key, "Content-Type": "application/json"}, &sr); err != nil {
		return nil, err
	}
	if sr.ID == "" {
		return nil, nil
	}
	var rr struct {
		Records []intelxRecord `json:"records"`
	}
	resultURL := i.baseURL + "/intelligent/search/result?limit=10&id=" + url.QueryEscape(sr.ID)
	if err := fetchJSON(ctx, client, http.MethodGet, resultURL, nil,
		map[string]string{"x-key": i.key}, &rr); err != nil {
		return nil, err
	}
	return rr.Records, nil
}
