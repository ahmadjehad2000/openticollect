package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := loadFrom(func(string) string { return "" })
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr default = %q", cfg.ListenAddr)
	}
	if cfg.DatabasePath != "./data/openticollect.db" {
		t.Errorf("DatabasePath default = %q", cfg.DatabasePath)
	}
	if cfg.SMTPPort != 587 {
		t.Errorf("SMTPPort default = %d", cfg.SMTPPort)
	}
	if !cfg.EnableAhmia {
		t.Error("EnableAhmia should default true")
	}
	if cfg.WebhookMinSeverity != "warn" || cfg.EmailMinSeverity != "critical" {
		t.Error("severity defaults wrong")
	}
}

func TestLoadParsesLists(t *testing.T) {
	env := map[string]string{
		"RSS_FEEDS":       "https://a/feed, https://b/feed ",
		"SMTP_TO":         "x@y.com,z@y.com",
		"WEBSCRAPER_URLS": "",
	}
	cfg, err := loadFrom(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RSSFeeds) != 2 || cfg.RSSFeeds[1] != "https://b/feed" {
		t.Errorf("RSSFeeds = %#v (whitespace must be trimmed)", cfg.RSSFeeds)
	}
	if len(cfg.SMTPTo) != 2 {
		t.Errorf("SMTPTo = %#v", cfg.SMTPTo)
	}
	if len(cfg.WebscraperURLs) != 0 {
		t.Errorf("empty list must yield nil/empty, got %#v", cfg.WebscraperURLs)
	}
}

func TestLoadRejectsBadSeverity(t *testing.T) {
	env := map[string]string{"WEBHOOK_MIN_SEVERITY": "loud"}
	if _, err := loadFrom(func(k string) string { return env[k] }); err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestLoadRejectsBadLogLevel(t *testing.T) {
	env := map[string]string{"LOG_LEVEL": "screaming"}
	if _, err := loadFrom(func(k string) string { return env[k] }); err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestMask(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "(not set)"},
		{"abc", "••••"},
		{"sk_secret1234", "••••1234"},
	}
	for _, c := range cases {
		if got := Mask(c.in); got != c.want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultRSSFeedsIncludeLeakTrackers(t *testing.T) {
	cfg, err := loadFrom(func(string) string { return "" })
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if len(cfg.RSSFeeds) < 6 {
		t.Fatalf("expected curated default feeds, got %d", len(cfg.RSSFeeds))
	}
	joined := strings.Join(cfg.RSSFeeds, " ")
	if !strings.Contains(joined, "ransomware.live") {
		t.Errorf("default feeds should include a ransomware leak tracker; got %v", cfg.RSSFeeds)
	}
}

func TestDefaultTelegramChannelsMonitored(t *testing.T) {
	cfg, err := loadFrom(func(string) string { return "" })
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if len(cfg.TelegramChannels) < 3 {
		t.Fatalf("expected curated default Telegram channels, got %d", len(cfg.TelegramChannels))
	}
	if !strings.Contains(strings.Join(cfg.TelegramChannels, " "), "vxunderground") {
		t.Errorf("default Telegram channels should include vxunderground; got %v", cfg.TelegramChannels)
	}
}

func TestTelegramChannelsOverridable(t *testing.T) {
	cfg, err := loadFrom(func(k string) string {
		if k == "TELEGRAM_CHANNELS" {
			return "@one, t.me/two"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("loadFrom: %v", err)
	}
	if len(cfg.TelegramChannels) != 2 {
		t.Fatalf("explicit TELEGRAM_CHANNELS must override the default, got %v", cfg.TelegramChannels)
	}
}
