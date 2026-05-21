package server

import (
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/models"
	"openticollect/internal/notifier"
)

// settingField describes one editable configuration value.
type settingField struct {
	Env     string
	Label   string
	Kind    string // "text" | "select" | "bool"
	Secret  bool
	Options []string
}

// settingGroups is the editable surface of the configuration. DATABASE_PATH and
// LISTEN_ADDR are intentionally excluded — they bootstrap the process.
var settingGroups = []struct {
	Name   string
	Fields []settingField
}{
	{"Core", []settingField{
		{Env: "LOG_LEVEL", Label: "Log level", Kind: "select", Options: []string{"debug", "info", "warn", "error"}},
		{Env: "BASIC_AUTH_USER", Label: "Basic auth user", Kind: "text"},
		{Env: "BASIC_AUTH_PASS", Label: "Basic auth password", Kind: "text", Secret: true},
	}},
	{"Notifiers", []settingField{
		{Env: "WEBHOOK_URL", Label: "Webhook URL", Kind: "text"},
		{Env: "WEBHOOK_SECRET", Label: "Webhook secret", Kind: "text", Secret: true},
		{Env: "WEBHOOK_MIN_SEVERITY", Label: "Webhook min severity", Kind: "select", Options: []string{"info", "warn", "critical"}},
		{Env: "SMTP_HOST", Label: "SMTP host", Kind: "text"},
		{Env: "SMTP_PORT", Label: "SMTP port", Kind: "text"},
		{Env: "SMTP_USER", Label: "SMTP user", Kind: "text"},
		{Env: "SMTP_PASS", Label: "SMTP password", Kind: "text", Secret: true},
		{Env: "SMTP_FROM", Label: "SMTP from", Kind: "text"},
		{Env: "SMTP_TO", Label: "SMTP recipients", Kind: "text"},
		{Env: "EMAIL_MIN_SEVERITY", Label: "Email min severity", Kind: "select", Options: []string{"info", "warn", "critical"}},
	}},
	{"Collector API keys", []settingField{
		{Env: "OTX_API_KEY", Label: "AlienVault OTX", Kind: "text", Secret: true},
		{Env: "ABUSEIPDB_API_KEY", Label: "AbuseIPDB", Kind: "text", Secret: true},
		{Env: "ABUSECH_AUTH_KEY", Label: "abuse.ch", Kind: "text", Secret: true},
		{Env: "PULSEDIVE_API_KEY", Label: "Pulsedive", Kind: "text", Secret: true},
		{Env: "INTELX_API_KEY", Label: "IntelX", Kind: "text", Secret: true},
		{Env: "NVD_API_KEY", Label: "NVD (optional)", Kind: "text", Secret: true},
	}},
	{"Sources", []settingField{
		{Env: "WEBSCRAPER_URLS", Label: "Web scraper URLs (comma-separated)", Kind: "text"},
		{Env: "RSS_FEEDS", Label: "RSS/Atom feeds (comma-separated)", Kind: "text"},
		{Env: "TELEGRAM_CHANNELS", Label: "Telegram channels (comma-separated)", Kind: "text"},
		{Env: "TOR_PROXY", Label: "Tor SOCKS5 proxy", Kind: "text"},
		{Env: "ONION_URLS", Label: ".onion watchlist (comma-separated)", Kind: "text"},
		{Env: "ENABLE_AHMIA", Label: "Ahmia dark-web search", Kind: "bool"},
	}},
}

type settingFieldView struct {
	settingField
	Value  string // current value, non-secret
	Masked string // masked current value, secret fields
	On     bool   // current state, bool fields
}

type settingsGroupView struct {
	Name   string
	Fields []settingFieldView
}

type settingsData struct {
	Groups []settingsGroupView
	Err    string
}

func buildSettingsView() []settingsGroupView {
	var out []settingsGroupView
	for _, g := range settingGroups {
		gv := settingsGroupView{Name: g.Name}
		for _, f := range g.Fields {
			cur := os.Getenv(f.Env)
			fv := settingFieldView{settingField: f}
			switch {
			case f.Secret:
				fv.Masked = config.Mask(cur)
			case f.Kind == "bool":
				fv.On = cur == "true"
			default:
				fv.Value = cur
			}
			gv.Fields = append(gv.Fields, fv)
		}
		out = append(out, gv)
	}
	return out
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, settingsData{Groups: buildSettingsView()})
}

func (s *Server) renderSettings(w http.ResponseWriter, d settingsData) {
	s.render(w, "settings", pageData{
		Nav: "settings", Title: "Settings", Heading: "Settings",
		Description: "Edit configuration here — saving applies it and restarts the service.",
		Data:        d,
	})
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Validate before persisting anything.
	for env, val := range map[string]string{
		"WEBHOOK_MIN_SEVERITY": strings.TrimSpace(r.FormValue("WEBHOOK_MIN_SEVERITY")),
		"EMAIL_MIN_SEVERITY":   strings.TrimSpace(r.FormValue("EMAIL_MIN_SEVERITY")),
	} {
		if val != "" && !models.ValidSeverity(val) {
			s.settingsError(w, env+" is invalid")
			return
		}
	}
	if lvl := strings.TrimSpace(r.FormValue("LOG_LEVEL")); lvl != "" &&
		lvl != "debug" && lvl != "info" && lvl != "warn" && lvl != "error" {
		s.settingsError(w, "LOG_LEVEL is invalid")
		return
	}
	if port := strings.TrimSpace(r.FormValue("SMTP_PORT")); port != "" {
		if _, err := strconv.Atoi(port); err != nil {
			s.settingsError(w, "SMTP_PORT must be a number")
			return
		}
	}

	// Persist each field. Secret fields left blank are kept unchanged.
	for _, g := range settingGroups {
		for _, f := range g.Fields {
			switch {
			case f.Kind == "bool":
				v := "false"
				if r.FormValue(f.Env) == "true" {
					v = "true"
				}
				if err := s.store.PutSetting(f.Env, v); err != nil {
					s.settingsError(w, err.Error())
					return
				}
			case f.Secret:
				v := strings.TrimSpace(r.FormValue(f.Env))
				if v == "" {
					continue // blank => keep current secret
				}
				if err := s.store.PutSetting(f.Env, v); err != nil {
					s.settingsError(w, err.Error())
					return
				}
			default:
				if err := s.store.PutSetting(f.Env, strings.TrimSpace(r.FormValue(f.Env))); err != nil {
					s.settingsError(w, err.Error())
					return
				}
			}
		}
	}

	if s.restart == nil {
		// No restart hook (e.g. tests) — just confirm.
		w.Header().Set("HX-Redirect", "/settings")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(restartPage))
	go s.restart()
}

func (s *Server) settingsError(w http.ResponseWriter, msg string) {
	s.renderSettings(w, settingsData{Groups: buildSettingsView(), Err: msg})
}

// restartPage is shown after a settings save; it reconnects once the service
// has restarted with the new configuration.
const restartPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="color-scheme" content="dark">
<meta http-equiv="refresh" content="5; url=/settings">
<title>Restarting · openTIcollect</title>
<link rel="icon" href="/static/favicon.svg">
<link rel="stylesheet" href="/static/style.css">
</head><body><main class="container"><div class="page-head"><h1>Configuration saved</h1>
<p class="muted">Applying the new settings and restarting the service — this page reconnects in a few seconds.</p>
</div></main></body></html>`

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
