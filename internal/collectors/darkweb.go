package collectors

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
	"openticollect/internal/models"
)

// Darkweb searches the Ahmia clear-net index of .onion sites and, when a Tor
// SOCKS5 proxy is configured, fetches a watchlist of .onion URLs directly.
type Darkweb struct {
	ahmiaEnabled bool
	ahmiaURL     string
	onionURLs    []string
}

func NewDarkweb(cfg *config.Config) *Darkweb {
	return &Darkweb{
		ahmiaEnabled: cfg.EnableAhmia,
		ahmiaURL:     "https://ahmia.fi",
		onionURLs:    cfg.OnionURLs,
	}
}

func (d *Darkweb) Name() string            { return "darkweb" }
func (d *Darkweb) Interval() time.Duration { return 60 * time.Minute }

func (d *Darkweb) MissingEnv(cfg *config.Config) []string {
	if !cfg.EnableAhmia && len(cfg.OnionURLs) == 0 {
		return []string{"ENABLE_AHMIA or ONION_URLS"}
	}
	return nil
}

func (d *Darkweb) Enabled(cfg *config.Config) bool { return len(d.MissingEnv(cfg)) == 0 }

func (d *Darkweb) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result

	if d.ahmiaEnabled {
		for _, kw := range in.Keywords {
			if !kw.Enabled {
				continue
			}
			findings, err := d.ahmiaSearch(ctx, in.HTTP, kw)
			if err != nil {
				in.Logger.Warn("darkweb: ahmia search failed", "term", kw.Value, "err", err)
				continue
			}
			res.ItemsFetched += len(findings)
			res.Findings = append(res.Findings, findings...)
		}
	}

	if len(d.onionURLs) > 0 {
		if in.Tor == nil {
			in.Logger.Warn("darkweb: ONION_URLS set but TOR_PROXY is unconfigured; skipping onion watchlist")
		} else {
			for _, onion := range d.onionURLs {
				doc, err := fetchDoc(ctx, in.Tor, onion)
				if err != nil {
					in.Logger.Warn("darkweb: onion fetch failed", "url", onion, "err", err)
					continue
				}
				res.ItemsFetched++
				text := strings.TrimSpace(doc.Find("body").Text())
				res.Findings = append(res.Findings, scanText("darkweb", onion, text, "", m)...)
			}
		}
	}
	return res, nil
}

// ahmiaSearch queries Ahmia for a keyword; every returned result is a hit for it.
func (d *Darkweb) ahmiaSearch(ctx context.Context, client *http.Client, kw models.Keyword) ([]models.Finding, error) {
	endpoint := d.ahmiaURL + "/search/?q=" + url.QueryEscape(kw.Value)
	doc, err := fetchDoc(ctx, client, endpoint)
	if err != nil {
		return nil, err
	}
	var findings []models.Finding
	doc.Find("li.result").Each(func(_ int, s *goquery.Selection) {
		title := strings.TrimSpace(s.Find("h4").Text())
		if title == "" {
			return
		}
		link, _ := s.Find("h4 a").Attr("href")
		findings = append(findings, models.Finding{
			Source:         "darkweb",
			SourceURL:      link,
			MatchedKeyword: kw.Value,
			Severity:       kw.Severity,
			Excerpt:        title,
			Hash:           models.HashFinding("darkweb", link, kw.Value),
			Status:         "new",
		})
	})
	return findings, nil
}
