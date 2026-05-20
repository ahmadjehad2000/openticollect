package collectors

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/PuerkitoBio/goquery"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// Pastes scrapes the Pastebin archive (then each raw paste, rate-limited) plus a
// best-effort scan of other paste sites. rentry has no public archive and is
// skipped by design.
type Pastes struct {
	archiveURL string
	rawBase    string
	extraURLs  []string
	pause      time.Duration // delay between raw fetches (Pastebin rate limit)
	maxPastes  int
}

func NewPastes(cfg *config.Config) *Pastes {
	return &Pastes{
		archiveURL: "https://pastebin.com/archive",
		rawBase:    "https://pastebin.com/raw/",
		extraURLs:  []string{"https://dpaste.com/"},
		pause:      time.Second,
		maxPastes:  20,
	}
}

func (p *Pastes) Name() string                          { return "pastes" }
func (p *Pastes) Interval() time.Duration                { return time.Minute }
func (p *Pastes) MissingEnv(cfg *config.Config) []string { return nil }
func (p *Pastes) Enabled(cfg *config.Config) bool        { return true }

var pasteKeyRe = regexp.MustCompile(`^/[a-zA-Z0-9]{8}$`)

func (p *Pastes) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result

	doc, err := fetchDoc(ctx, in.HTTP, p.archiveURL)
	if err != nil {
		// Pastebin is frequently Cloudflare-protected; log and fail this run
		// without affecting other collectors.
		in.Logger.Warn("pastes: pastebin archive unreachable", "err", err)
		return res, fmt.Errorf("pastes: archive: %w", err)
	}

	seen := map[string]bool{}
	var keys []string
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		if pasteKeyRe.MatchString(href) && !seen[href] {
			seen[href] = true
			keys = append(keys, href[1:])
		}
	})

	for i, key := range keys {
		if i >= p.maxPastes {
			break
		}
		if i > 0 {
			pacePause(ctx, p.pause)
		}
		body, err := fetchText(ctx, in.HTTP, p.rawBase+key, nil)
		if err != nil {
			in.Logger.Warn("pastes: raw fetch failed", "key", key, "err", err)
			continue
		}
		res.ItemsFetched++
		res.Findings = append(res.Findings,
			scanText("pastebin", "https://pastebin.com/"+key, body, "", m)...)
	}

	for _, u := range p.extraURLs {
		body, err := fetchText(ctx, in.HTTP, u, nil)
		if err != nil {
			in.Logger.Warn("pastes: extra paste site failed", "url", u, "err", err)
			continue
		}
		res.ItemsFetched++
		res.Findings = append(res.Findings, scanText("pastes", u, body, "", m)...)
	}
	return res, nil
}

// pacePause waits d, or returns early if ctx is cancelled.
func pacePause(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
