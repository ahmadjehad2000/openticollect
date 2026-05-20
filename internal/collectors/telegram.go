package collectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"openticollect/internal/config"
	"openticollect/internal/matcher"
)

// Telegram scrapes public channels via their t.me/s/<channel> preview pages.
// No credentials are needed; only publicly visible messages are seen.
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
	fetched := 0

	for _, raw := range tg.channels {
		ch := channelName(raw)
		if ch == "" {
			continue
		}
		doc, err := fetchDoc(ctx, in.HTTP, tg.baseURL+"/s/"+ch)
		if err != nil {
			in.Logger.Warn("telegram: channel fetch failed", "channel", ch, "err", err)
			continue
		}
		fetched++
		doc.Find(".tgme_widget_message").Each(func(_ int, s *goquery.Selection) {
			res.ItemsFetched++
			text := strings.TrimSpace(s.Find(".tgme_widget_message_text").Text())
			link, ok := s.Find(".tgme_widget_message_date").Attr("href")
			if !ok || link == "" {
				link = tg.baseURL + "/" + ch
			}
			res.Findings = append(res.Findings, scanText("telegram", link, text, "", m)...)
		})
	}
	if fetched == 0 && len(tg.channels) > 0 {
		return res, fmt.Errorf("telegram: no channels could be fetched")
	}
	return res, nil
}
