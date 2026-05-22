package collectors

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// maxXQueries caps the per-run keyword searches issued to X.
const maxXQueries = 8

// X scans X (formerly Twitter) for watchlist-keyword mentions — a brand asset
// or a leak being discussed publicly. This is the brand-protection mission:
// threat actors and leak brokers routinely announce breaches and dumps on X.
//
// X requires authentication to read, so the collector goes through Nitter, the
// open-source X front-end, which exposes public search and timelines without
// an API key — keeping the collector keyless and within the project's
// free-sources rule. Nitter instances are volatile: configure one or more
// reachable instances in X_NITTER_INSTANCES (a self-hosted instance is the
// most reliable). The collector tries them in order and fails gracefully when
// none responds.
type X struct {
	instances []string // Nitter base URLs, tried in order
	accounts  []string // optional X handles whose timelines are also scanned
}

func NewX(cfg *config.Config) *X {
	return &X{instances: cfg.XNitterInstances, accounts: cfg.XAccounts}
}

func (x *X) Name() string            { return "x" }
func (x *X) Interval() time.Duration { return 15 * time.Minute }

func (x *X) MissingEnv(cfg *config.Config) []string {
	if len(cfg.XNitterInstances) == 0 {
		return []string{"X_NITTER_INSTANCES"}
	}
	return nil
}

func (x *X) Enabled(cfg *config.Config) bool { return len(x.MissingEnv(cfg)) == 0 }

// Run searches X for every literal watchlist keyword and, optionally, scans
// the timelines of the configured accounts.
func (x *X) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result

	// Literal keywords are searched server-side; regex keywords are still
	// caught by scanning whatever each page returns.
	var literals []string
	for _, k := range in.Keywords {
		if k.Enabled && k.Kind == "literal" {
			literals = append(literals, k.Value)
		}
	}
	if len(literals) > maxXQueries {
		literals = literals[:maxXQueries]
	}

	inst := x.pickInstance(ctx, in)
	if inst == "" {
		return res, fmt.Errorf("x: no Nitter instance reachable")
	}

	for _, kw := range literals {
		x.scan(ctx, in, m, &res, inst+"/search?f=tweets&q="+url.QueryEscape(kw))
	}
	for _, raw := range x.accounts {
		if h := xHandle(raw); h != "" {
			x.scan(ctx, in, m, &res, inst+"/"+h)
		}
	}
	return res, nil
}

// pickInstance returns the first configured Nitter instance that serves a
// parseable timeline, or "" when none responds.
func (x *X) pickInstance(ctx context.Context, in Input) string {
	for _, candidate := range x.instances {
		base := strings.TrimRight(strings.TrimSpace(candidate), "/")
		if base == "" {
			continue
		}
		doc, err := fetchDoc(ctx, in.HTTP, base+"/search?f=tweets&q=security")
		if err != nil {
			in.Logger.Warn("x: nitter instance unreachable", "instance", base, "err", err)
			continue
		}
		if doc.Find(".timeline-item").Length() == 0 && doc.Find(".timeline").Length() == 0 {
			in.Logger.Warn("x: nitter instance returned no timeline", "instance", base)
			continue
		}
		return base
	}
	return ""
}

// scan fetches one Nitter page and turns each tweet into keyword findings.
func (x *X) scan(ctx context.Context, in Input, m *matcher.Matcher, res *Result, pageURL string) {
	doc, err := fetchDoc(ctx, in.HTTP, pageURL)
	if err != nil {
		in.Logger.Warn("x: fetch failed", "url", pageURL, "err", err)
		return
	}
	doc.Find(".timeline-item").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Find(".tweet-content").Text())
		if text == "" {
			return // "show more" rows, pinned markers, etc.
		}
		res.ItemsFetched++
		link := ""
		if href, ok := s.Find("a.tweet-link").Attr("href"); ok {
			link = xPermalink(href)
		}
		res.Findings = append(res.Findings, scanText("x", link, text, "", m)...)
	})
}

// xHandle normalizes "@foo", "x.com/foo" or "https://twitter.com/foo" to "foo".
func xHandle(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "@")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// xPermalink turns a Nitter-relative tweet href ("/user/status/123#m") into
// the canonical x.com URL, so a finding links to the real post rather than to
// a volatile Nitter instance. It returns "" for an unusable href.
func xPermalink(href string) string {
	if i := strings.IndexAny(href, "#?"); i >= 0 {
		href = href[:i]
	}
	href = strings.Trim(strings.TrimSpace(href), "/")
	if href == "" {
		return ""
	}
	return "https://x.com/" + href
}
