package collectors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temoto/robotstxt"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
	"openticollect/internal/version"
)

// Webscraper fetches each URL in WEBSCRAPER_URLS (honouring robots.txt), extracts
// visible text, and matches it against the watchlist.
type Webscraper struct {
	urls []string
}

func NewWebscraper(cfg *config.Config) *Webscraper {
	return &Webscraper{urls: cfg.WebscraperURLs}
}

func (w *Webscraper) Name() string            { return "webscraper" }
func (w *Webscraper) Interval() time.Duration { return 30 * time.Minute }

func (w *Webscraper) MissingEnv(cfg *config.Config) []string {
	if len(cfg.WebscraperURLs) == 0 {
		return []string{"WEBSCRAPER_URLS"}
	}
	return nil
}

func (w *Webscraper) Enabled(cfg *config.Config) bool { return len(w.MissingEnv(cfg)) == 0 }

func (w *Webscraper) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result
	attempted, succeeded := 0, 0

	for _, raw := range w.urls {
		u, err := url.Parse(raw)
		if err != nil {
			in.Logger.Warn("webscraper: bad URL", "url", raw, "err", err)
			continue
		}
		if !w.allowed(ctx, in.HTTP, u) {
			in.Logger.Info("webscraper: disallowed by robots.txt", "url", raw)
			continue
		}
		attempted++
		doc, err := fetchDoc(ctx, in.HTTP, raw)
		if err != nil {
			in.Logger.Warn("webscraper: fetch failed", "url", raw, "err", err)
			continue
		}
		succeeded++
		res.ItemsFetched++
		text := strings.TrimSpace(doc.Find("body").Text())
		if text == "" {
			text = strings.TrimSpace(doc.Text())
		}
		res.Findings = append(res.Findings, scanText("webscraper", raw, text, "", m)...)
	}

	if attempted > 0 && succeeded == 0 {
		return res, fmt.Errorf("webscraper: all %d scrapes failed", attempted)
	}
	return res, nil
}

// allowed reports whether the site's robots.txt permits scraping u.Path.
// A missing or unparseable robots.txt is treated as permissive.
func (w *Webscraper) allowed(ctx context.Context, client *http.Client, u *url.URL) bool {
	body, err := fetchText(ctx, client, u.Scheme+"://"+u.Host+"/robots.txt", nil)
	if err != nil {
		return true
	}
	data, err := robotstxt.FromString(body)
	if err != nil {
		return true
	}
	return data.TestAgent(u.Path, version.String())
}
