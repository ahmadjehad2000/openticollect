package collectors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/temoto/robotstxt"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
	"openticollect/internal/version"
)

// Webscraper fetches each URL in WEBSCRAPER_URLS, follows same-host links one
// level deep, and matches the watchlist against page text, titles, meta
// descriptions, link targets and image alt text. robots.txt is honored for
// every URL fetched.
type Webscraper struct {
	urls       []string
	maxDepth   int           // 0 = seeds only, 1 = seeds + linked pages
	maxPerSeed int           // links followed from a single page
	maxTotal   int           // hard cap on pages fetched per run
	pause      time.Duration // politeness delay between fetches
}

func NewWebscraper(cfg *config.Config) *Webscraper {
	return &Webscraper{
		urls:       cfg.WebscraperURLs,
		maxDepth:   1,
		maxPerSeed: 8,
		maxTotal:   40,
		pause:      300 * time.Millisecond,
	}
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

type scrapeTask struct {
	url   string
	depth int
}

func (w *Webscraper) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result

	visited := map[string]bool{}
	robots := map[string]*robotstxt.RobotsData{}
	attempted, succeeded := 0, 0

	queue := make([]scrapeTask, 0, len(w.urls))
	for _, u := range w.urls {
		queue = append(queue, scrapeTask{url: u, depth: 0})
	}

	for len(queue) > 0 && len(visited) < w.maxTotal {
		task := queue[0]
		queue = queue[1:]

		norm := normalizeURL(task.url)
		if norm == "" || visited[norm] {
			continue
		}
		visited[norm] = true

		u, err := url.Parse(task.url)
		if err != nil {
			in.Logger.Warn("webscraper: bad URL", "url", task.url, "err", err)
			continue
		}
		if !w.robotsAllow(ctx, in.HTTP, robots, u) {
			in.Logger.Info("webscraper: disallowed by robots.txt", "url", task.url)
			continue
		}

		if attempted > 0 {
			pacePause(ctx, w.pause)
		}
		attempted++
		doc, err := fetchDoc(ctx, in.HTTP, task.url)
		if err != nil {
			in.Logger.Warn("webscraper: fetch failed", "url", task.url, "err", err)
			continue
		}
		succeeded++
		res.ItemsFetched++

		links := sameHostLinks(doc, u)
		corpus := extractCorpus(doc)
		res.Findings = append(res.Findings, scanText("webscraper", task.url, corpus, "", m)...)

		if task.depth < w.maxDepth {
			added := 0
			for _, l := range links {
				if added >= w.maxPerSeed {
					break
				}
				if visited[normalizeURL(l)] {
					continue
				}
				queue = append(queue, scrapeTask{url: l, depth: task.depth + 1})
				added++
			}
		}
	}

	if attempted > 0 && succeeded == 0 {
		return res, fmt.Errorf("webscraper: all %d fetches failed", attempted)
	}
	return res, nil
}

// extractCorpus builds the searchable text of a page: title, meta description,
// visible body text, link targets and image alt text. Script and style content
// is dropped so matches reflect real content rather than embedded code.
func extractCorpus(doc *goquery.Document) string {
	doc.Find("script, style, noscript, template").Remove()

	var b strings.Builder
	b.WriteString(strings.TrimSpace(doc.Find("title").Text()))
	b.WriteString("\n")
	doc.Find(`meta[name="description"], meta[property="og:description"]`).Each(
		func(_ int, s *goquery.Selection) {
			if c, ok := s.Attr("content"); ok {
				b.WriteString(c)
				b.WriteString("\n")
			}
		})
	b.WriteString(strings.TrimSpace(doc.Find("body").Text()))
	b.WriteString("\n")
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		if h, ok := s.Attr("href"); ok {
			b.WriteString(h)
			b.WriteString(" ")
		}
	})
	doc.Find("img[alt]").Each(func(_ int, s *goquery.Selection) {
		if a, ok := s.Attr("alt"); ok {
			b.WriteString(a)
			b.WriteString(" ")
		}
	})

	corpus := b.String()
	const maxCorpus = 256 * 1024
	if len(corpus) > maxCorpus {
		corpus = corpus[:maxCorpus]
	}
	return corpus
}

// sameHostLinks returns absolute http(s) links from doc that share base's host.
func sameHostLinks(doc *goquery.Document, base *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if !ok {
			return
		}
		ref, err := url.Parse(strings.TrimSpace(href))
		if err != nil {
			return
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			return
		}
		if abs.Host != base.Host {
			return
		}
		abs.Fragment = ""
		if u := abs.String(); !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	})
	return out
}

func normalizeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

// robotsAllow reports whether u.Path may be fetched, caching robots.txt per
// host. A missing or unparseable robots.txt is treated as permissive.
func (w *Webscraper) robotsAllow(ctx context.Context, client *http.Client,
	cache map[string]*robotstxt.RobotsData, u *url.URL) bool {
	host := u.Scheme + "://" + u.Host
	data, cached := cache[host]
	if !cached {
		if body, err := fetchText(ctx, client, host+"/robots.txt", nil); err == nil {
			if parsed, perr := robotstxt.FromString(body); perr == nil {
				data = parsed
			}
		}
		cache[host] = data // nil is cached too — only fetch robots.txt once
	}
	if data == nil {
		return true
	}
	return data.TestAgent(u.Path, version.String())
}
