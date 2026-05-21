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
			d.crawlOnions(ctx, in, m, &res)
		}
	}
	return res, nil
}

// crawlOnions fetches each watchlisted .onion site and follows its same-host
// links one level deep, so a single configured onion yields broader coverage.
func (d *Darkweb) crawlOnions(ctx context.Context, in Input, m *matcher.Matcher, res *Result) {
	const maxOnionPages = 30
	const maxOnionLinks = 6

	visited := map[string]bool{}
	queue := make([]scrapeTask, 0, len(d.onionURLs))
	for _, o := range d.onionURLs {
		queue = append(queue, scrapeTask{url: o, depth: 0})
	}

	for len(queue) > 0 && len(visited) < maxOnionPages {
		task := queue[0]
		queue = queue[1:]

		norm := normalizeURL(task.url)
		if norm == "" || visited[norm] {
			continue
		}
		visited[norm] = true

		u, err := url.Parse(task.url)
		if err != nil {
			in.Logger.Warn("darkweb: bad onion URL", "url", task.url, "err", err)
			continue
		}
		doc, err := fetchDoc(ctx, in.Tor, task.url)
		if err != nil {
			in.Logger.Warn("darkweb: onion fetch failed", "url", task.url, "err", err)
			continue
		}
		res.ItemsFetched++
		links := sameHostLinks(doc, u)
		res.Findings = append(res.Findings,
			scanText("darkweb", task.url, extractCorpus(doc), "", m)...)

		if task.depth < 1 {
			added := 0
			for _, l := range links {
				if added >= maxOnionLinks {
					break
				}
				if !visited[normalizeURL(l)] {
					queue = append(queue, scrapeTask{url: l, depth: task.depth + 1})
					added++
				}
			}
		}
	}
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
