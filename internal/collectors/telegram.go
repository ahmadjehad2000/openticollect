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

// maxTelegramQueries caps the per-keyword searches issued to a single channel.
const maxTelegramQueries = 8

// Telegram scrapes public channels via their t.me/s/<channel> preview pages.
// Beyond the recent-message scan it issues a per-keyword search
// (t.me/s/<channel>?q=<keyword>) so historical mentions are found too.
type Telegram struct {
	channels []string
	baseURL  string
}

func NewTelegram(cfg *config.Config) *Telegram {
	return &Telegram{channels: cfg.TelegramChannels, baseURL: "https://t.me"}
}

func (tg *Telegram) Name() string            { return "telegram" }
func (tg *Telegram) Interval() time.Duration { return 10 * time.Minute }

func (tg *Telegram) MissingEnv(cfg *config.Config) []string {
	if len(cfg.TelegramChannels) == 0 {
		return []string{"TELEGRAM_CHANNELS"}
	}
	return nil
}

func (tg *Telegram) Enabled(cfg *config.Config) bool { return len(tg.MissingEnv(cfg)) == 0 }

// channelName normalizes "@foo", "t.me/foo" or "https://t.me/foo" to "foo".
func channelName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "@")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func (tg *Telegram) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result

	// Literal keywords can be searched server-side; regex keywords are caught
	// by the recent-message scan.
	var literals []string
	for _, k := range in.Keywords {
		if k.Enabled && k.Kind == "literal" {
			literals = append(literals, k.Value)
		}
	}
	if len(literals) > maxTelegramQueries {
		literals = literals[:maxTelegramQueries]
	}

	fetched := 0
	for _, raw := range tg.channels {
		ch := channelName(raw)
		if ch == "" {
			continue
		}

		// Recent messages — matched against every keyword.
		if tg.scan(ctx, in, m, &res, tg.baseURL+"/s/"+ch, ch) {
			fetched++
		}
		// Per-keyword search inside the channel.
		for _, kw := range literals {
			u := tg.baseURL + "/s/" + ch + "?q=" + url.QueryEscape(kw)
			if tg.scan(ctx, in, m, &res, u, ch) {
				fetched++
			}
		}
	}
	if fetched == 0 && len(tg.channels) > 0 {
		return res, fmt.Errorf("telegram: no channels could be fetched")
	}
	return res, nil
}

// scan fetches one t.me/s page and appends findings; it returns false on error.
func (tg *Telegram) scan(ctx context.Context, in Input, m *matcher.Matcher,
	res *Result, pageURL, channel string) bool {
	doc, err := fetchDoc(ctx, in.HTTP, pageURL)
	if err != nil {
		in.Logger.Warn("telegram: fetch failed", "url", pageURL, "err", err)
		return false
	}
	doc.Find(".tgme_widget_message").Each(func(_ int, s *goquery.Selection) {
		res.ItemsFetched++
		text := strings.TrimSpace(s.Find(".tgme_widget_message_text").Text())
		link, ok := s.Find(".tgme_widget_message_date").Attr("href")
		if !ok || link == "" {
			link = tg.baseURL + "/" + channel
		}
		res.Findings = append(res.Findings, scanText("telegram", link, text, "", m)...)
	})
	return true
}
