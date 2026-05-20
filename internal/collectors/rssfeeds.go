package collectors

import (
	"context"
	"fmt"
	"time"

	"github.com/mmcdole/gofeed"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// RSSFeeds collects from the RSS/Atom feeds listed in RSS_FEEDS.
type RSSFeeds struct {
	feeds []string
}

func NewRSSFeeds(cfg *config.Config) *RSSFeeds {
	return &RSSFeeds{feeds: cfg.RSSFeeds}
}

func (r *RSSFeeds) Name() string            { return "rssfeeds" }
func (r *RSSFeeds) Interval() time.Duration { return 15 * time.Minute }

func (r *RSSFeeds) MissingEnv(cfg *config.Config) []string {
	if len(cfg.RSSFeeds) == 0 {
		return []string{"RSS_FEEDS"}
	}
	return nil
}

func (r *RSSFeeds) Enabled(cfg *config.Config) bool {
	return len(r.MissingEnv(cfg)) == 0
}

func (r *RSSFeeds) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	parser := gofeed.NewParser()
	parser.Client = in.HTTP

	var res Result
	parsed := 0
	for _, url := range r.feeds {
		feed, err := parser.ParseURLWithContext(url, ctx)
		if err != nil {
			in.Logger.Warn("rssfeeds: feed parse failed", "url", url, "err", err)
			continue
		}
		parsed++
		for _, item := range feed.Items {
			res.ItemsFetched++
			text := item.Title + "\n" + item.Description + "\n" + item.Content
			res.Findings = append(res.Findings, scanText("rssfeeds", item.Link, text, "", m)...)
		}
	}
	if parsed == 0 && len(r.feeds) > 0 {
		return res, fmt.Errorf("rssfeeds: all %d feeds failed", len(r.feeds))
	}
	return res, nil
}
