package server

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/models"
	"openticollect/internal/notifier"
)

type settingRow struct {
	Key   string
	Value string
}

type settingsData struct {
	Core       []settingRow
	Notifiers  []settingRow
	Collectors []settingRow
	Web        []settingRow
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	c := s.cfg
	d := settingsData{
		Core: []settingRow{
			{"LISTEN_ADDR", c.ListenAddr},
			{"DATABASE_PATH", c.DatabasePath},
			{"LOG_LEVEL", c.LogLevel},
			{"BASIC_AUTH_USER", orDash(c.BasicAuthUser)},
			{"BASIC_AUTH_PASS", config.Mask(c.BasicAuthPass)},
		},
		Notifiers: []settingRow{
			{"WEBHOOK_URL", orDash(c.WebhookURL)},
			{"WEBHOOK_SECRET", config.Mask(c.WebhookSecret)},
			{"WEBHOOK_MIN_SEVERITY", c.WebhookMinSeverity},
			{"SMTP_HOST", orDash(c.SMTPHost)},
			{"SMTP_PORT", strconv.Itoa(c.SMTPPort)},
			{"SMTP_USER", orDash(c.SMTPUser)},
			{"SMTP_PASS", config.Mask(c.SMTPPass)},
			{"SMTP_FROM", orDash(c.SMTPFrom)},
			{"SMTP_TO", orDash(strings.Join(c.SMTPTo, ", "))},
			{"EMAIL_MIN_SEVERITY", c.EmailMinSeverity},
		},
		Collectors: []settingRow{
			{"OTX_API_KEY", config.Mask(c.OTXAPIKey)},
			{"ABUSEIPDB_API_KEY", config.Mask(c.AbuseIPDBKey)},
			{"ABUSECH_AUTH_KEY", config.Mask(c.AbuseCHKey)},
			{"PULSEDIVE_API_KEY", config.Mask(c.PulsediveKey)},
			{"INTELX_API_KEY", config.Mask(c.IntelXKey)},
			{"NVD_API_KEY", config.Mask(c.NVDAPIKey)},
		},
		Web: []settingRow{
			{"WEBSCRAPER_URLS", orDash(strings.Join(c.WebscraperURLs, ", "))},
			{"RSS_FEEDS", orDash(strings.Join(c.RSSFeeds, ", "))},
			{"TELEGRAM_CHANNELS", orDash(strings.Join(c.TelegramChannels, ", "))},
			{"TOR_PROXY", orDash(c.TorProxy)},
			{"ONION_URLS", orDash(strings.Join(c.OnionURLs, ", "))},
			{"ENABLE_AHMIA", strconv.FormatBool(c.EnableAhmia)},
		},
	}
	s.render(w, "settings", pageData{
		Nav: "settings", Title: "Settings", Heading: "Settings",
		Description: "Resolved configuration and notifier tests.", Data: d,
	})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	wh := notifier.NewWebhookSink(s.cfg.WebhookURL, s.cfg.WebhookSecret,
		"info", collectors.DefaultHTTPClient())
	if wh == nil {
		w.Write([]byte(`<span class="status-err">WEBHOOK_URL not configured</span>`))
		return
	}
	if err := wh.Send(r.Context(), testFinding()); err != nil {
		w.Write([]byte(`<span class="status-err">` +
			template.HTMLEscapeString(err.Error()) + `</span>`))
		return
	}
	w.Write([]byte(`<span class="status-ok">Test webhook delivered</span>`))
}

func (s *Server) handleTestEmail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	em := notifier.NewEmailSink(s.cfg.SMTPHost, s.cfg.SMTPPort, s.cfg.SMTPUser,
		s.cfg.SMTPPass, s.cfg.SMTPFrom, s.cfg.SMTPTo, "info")
	if em == nil {
		w.Write([]byte(`<span class="status-err">SMTP is not fully configured</span>`))
		return
	}
	if err := em.Send(r.Context(), testFinding()); err != nil {
		w.Write([]byte(`<span class="status-err">` +
			template.HTMLEscapeString(err.Error()) + `</span>`))
		return
	}
	w.Write([]byte(`<span class="status-ok">Test email delivered</span>`))
}

func testFinding() models.Finding {
	return models.Finding{
		Source:         "openticollect",
		MatchedKeyword: "test",
		Severity:       "info",
		Excerpt:        "This is a test alert from openTIcollect.",
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
