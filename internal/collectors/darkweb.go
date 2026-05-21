package collectors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
	"openticollect/internal/models"
)

const (
	// maxAhmiaResults caps the Ahmia hits processed per keyword.
	maxAhmiaResults = 20
	// maxOnionFetch caps how many .onion result pages are fetched via Tor per
	// run. Kept small — Tor fetches are slow and the run has a time budget.
	maxOnionFetch = 3
)

// Darkweb discovers dark-web content two ways: it searches the Ahmia clear-net
// index, and — when a Tor SOCKS5 proxy is configured — fetches the actual
// .onion result pages plus a watchlist of .onion URLs directly over Tor.
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

type onionHit struct {
	url   string
	title string
	desc  string
}

func (d *Darkweb) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result

	if d.ahmiaEnabled {
		token, err := d.ahmiaToken(ctx, in.HTTP)
		if err != nil {
			in.Logger.Warn("darkweb: ahmia unavailable", "err", err)
		} else {
			d.searchAhmia(ctx, in, m, token, &res)
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

// searchAhmia runs an Ahmia search per keyword, records each result, and — when
// Tor is available — fetches the actual .onion pages and scans their content.
func (d *Darkweb) searchAhmia(ctx context.Context, in Input, m *matcher.Matcher,
	token url.Values, res *Result) {
	onionFetched := 0
	for _, kw := range in.Keywords {
		if !kw.Enabled {
			continue
		}
		hits, err := d.ahmiaSearch(ctx, in.HTTP, token, kw.Value)
		if err != nil {
			in.Logger.Warn("darkweb: ahmia search failed", "term", kw.Value, "err", err)
			continue
		}
		for _, h := range hits {
			res.ItemsFetched++
			res.Findings = append(res.Findings, models.Finding{
				Source:         "darkweb",
				SourceURL:      h.url,
				MatchedKeyword: kw.Value,
				Severity:       kw.Severity,
				Excerpt:        strings.TrimSpace(h.title + " — " + h.desc),
				Hash:           models.HashFinding("darkweb", h.url, kw.Value),
				Status:         "new",
			})
		}
		// Fetch the real .onion pages over Tor and scan their content — this
		// goes beyond Ahmia's index to the dark-web sources themselves.
		if in.Tor == nil {
			continue
		}
		for _, h := range hits {
			if onionFetched >= maxOnionFetch {
				return
			}
			onionFetched++
			doc, ferr := fetchDoc(ctx, in.Tor, h.url)
			if ferr != nil {
				in.Logger.Warn("darkweb: onion fetch failed", "url", h.url, "err", ferr)
				continue
			}
			res.ItemsFetched++
			res.Findings = append(res.Findings,
				scanText("darkweb", h.url, extractCorpus(doc), "", m)...)
		}
	}
}

// ahmiaToken fetches Ahmia's home page and extracts the hidden form token that
// its search endpoint now requires.
func (d *Darkweb) ahmiaToken(ctx context.Context, client *http.Client) (url.Values, error) {
	doc, err := fetchDoc(ctx, client, d.ahmiaURL+"/")
	if err != nil {
		return nil, fmt.Errorf("ahmia home: %w", err)
	}
	token := url.Values{}
	doc.Find("#searchForm input[type=hidden]").Each(func(_ int, s *goquery.Selection) {
		if name, ok := s.Attr("name"); ok && name != "" {
			val, _ := s.Attr("value")
			token.Set(name, val)
		}
	})
	return token, nil
}

// ahmiaSearch queries Ahmia for a keyword and returns the onion results.
func (d *Darkweb) ahmiaSearch(ctx context.Context, client *http.Client,
	token url.Values, keyword string) ([]onionHit, error) {
	q := url.Values{}
	q.Set("q", keyword)
	for k, vs := range token {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	doc, err := fetchDoc(ctx, client, d.ahmiaURL+"/search/?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var hits []onionHit
	doc.Find("li.result").EachWithBreak(func(_ int, s *goquery.Selection) bool {
		a := s.Find("h4 a").First()
		title := strings.TrimSpace(a.Text())
		onion := ahmiaOnionURL(a.AttrOr("href", ""))
		if title != "" && onion != "" {
			hits = append(hits, onionHit{
				url:   onion,
				title: title,
				desc:  strings.TrimSpace(s.Find("p").First().Text()),
			})
		}
		return len(hits) < maxAhmiaResults
	})
	return hits, nil
}

// ahmiaOnionURL extracts the real .onion URL from an Ahmia result link, which
// is a /search/redirect?...&redirect_url=<onion> wrapper.
func ahmiaOnionURL(href string) string {
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	if ru := u.Query().Get("redirect_url"); ru != "" {
		return ru
	}
	if strings.Contains(href, ".onion") {
		return href
	}
	return ""
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
