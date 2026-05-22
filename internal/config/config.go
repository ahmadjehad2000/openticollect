// Package config loads and validates runtime configuration from the environment.
package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"openticollect/internal/models"
)

type Config struct {
	ListenAddr    string
	DatabasePath  string
	LogLevel      string
	BasicAuthUser string
	BasicAuthPass string
	APIKey        string

	WebhookURL         string
	WebhookSecret      string
	WebhookMinSeverity string
	SMTPHost           string
	SMTPPort           int
	SMTPUser           string
	SMTPPass           string
	SMTPFrom           string
	SMTPTo             []string
	EmailMinSeverity   string

	OTXAPIKey    string
	AbuseIPDBKey string
	AbuseCHKey   string
	PulsediveKey string
	IntelXKey    string
	NVDAPIKey    string

	WebscraperURLs   []string
	SecretScanURLs   []string
	RSSFeeds         []string
	TelegramChannels []string

	TorProxy    string
	OnionURLs   []string
	EnableAhmia bool

	// FetchWindowDays is how far back time-windowed collectors look.
	FetchWindowDays int
}

// defaultRSSFeeds is the out-of-the-box watchlist: general security/breach
// reporting plus dedicated ransomware/data-leak trackers. Leak trackers are
// the highest-signal sources for the brand-protection mission.
const defaultRSSFeeds = "https://www.databreaches.net/feed/," +
	"https://krebsonsecurity.com/feed/," +
	"https://www.bleepingcomputer.com/feed/," +
	"https://feeds.feedburner.com/TheHackersNews," +
	"https://www.darkreading.com/rss.xml," +
	"https://therecord.media/feed/," +
	"https://ransomware.live/rss.xml," +
	"https://www.ransomlook.io/rss"

// defaultTelegramChannels is the out-of-the-box public Telegram watchlist. The
// telegram collector scrapes each channel's public t.me/s/ preview feed for
// watchlist-keyword mentions — leak/breach chatter naming a brand asset.
//
// Only channels verified live at the time of writing are listed: the criminal
// Telegram landscape is highly volatile (Telegram's 2025 enforcement removes
// 100k+ channels/day), so most published "leak channel" handles are already
// dead. Curate this list and add more on the Settings page as the ecosystem
// shifts — a dead channel is harmless (it is logged and skipped).
const defaultTelegramChannels = "vxunderground," + // malware & breach/ransomware intel
	"darkwebinformer_news," + // data-breach / leak / ransomware reporting
	"nusacloud" // credential-dump / stealer-log channel

// Load reads .env (if present) then the process environment.
func Load() (*Config, error) {
	_ = godotenv.Load() // absent .env is fine
	return loadFrom(getenvOS)
}

// loadFrom is the testable core; getenv resolves a single variable.
func loadFrom(getenv func(string) string) (*Config, error) {
	str := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}

	cfg := &Config{
		ListenAddr:    str("LISTEN_ADDR", ":8080"),
		DatabasePath:  str("DATABASE_PATH", "./data/openticollect.db"),
		LogLevel:      str("LOG_LEVEL", "info"),
		BasicAuthUser: getenv("BASIC_AUTH_USER"),
		BasicAuthPass: getenv("BASIC_AUTH_PASS"),
		APIKey:        getenv("API_KEY"),

		WebhookURL:         getenv("WEBHOOK_URL"),
		WebhookSecret:      getenv("WEBHOOK_SECRET"),
		WebhookMinSeverity: str("WEBHOOK_MIN_SEVERITY", "warn"),
		SMTPHost:           getenv("SMTP_HOST"),
		SMTPUser:           getenv("SMTP_USER"),
		SMTPPass:           getenv("SMTP_PASS"),
		SMTPFrom:           getenv("SMTP_FROM"),
		SMTPTo:             splitList(getenv("SMTP_TO")),
		EmailMinSeverity:   str("EMAIL_MIN_SEVERITY", "critical"),

		OTXAPIKey:    getenv("OTX_API_KEY"),
		AbuseIPDBKey: getenv("ABUSEIPDB_API_KEY"),
		AbuseCHKey:   getenv("ABUSECH_AUTH_KEY"),
		PulsediveKey: getenv("PULSEDIVE_API_KEY"),
		IntelXKey:    getenv("INTELX_API_KEY"),
		NVDAPIKey:    getenv("NVD_API_KEY"),

		WebscraperURLs:   splitList(getenv("WEBSCRAPER_URLS")),
		SecretScanURLs:   splitList(getenv("SECRETSCAN_URLS")),
		RSSFeeds:         splitList(str("RSS_FEEDS", defaultRSSFeeds)),
		TelegramChannels: splitList(str("TELEGRAM_CHANNELS", defaultTelegramChannels)),

		TorProxy:    getenv("TOR_PROXY"),
		OnionURLs:   splitList(getenv("ONION_URLS")),
		EnableAhmia: str("ENABLE_AHMIA", "true") == "true",
	}

	port, err := strconv.Atoi(str("SMTP_PORT", "587"))
	if err != nil {
		return nil, fmt.Errorf("config: SMTP_PORT invalid: %w", err)
	}
	cfg.SMTPPort = port

	window, err := strconv.Atoi(str("FETCH_WINDOW_DAYS", "30"))
	if err != nil {
		return nil, fmt.Errorf("config: FETCH_WINDOW_DAYS invalid: %w", err)
	}
	if window < 1 {
		window = 1
	}
	cfg.FetchWindowDays = window

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("config: LOG_LEVEL invalid: %q", cfg.LogLevel)
	}
	for key, val := range map[string]string{
		"WEBHOOK_MIN_SEVERITY": cfg.WebhookMinSeverity,
		"EMAIL_MIN_SEVERITY":   cfg.EmailMinSeverity,
	} {
		if !models.ValidSeverity(val) {
			return nil, fmt.Errorf("config: %s invalid: %q", key, val)
		}
	}
	return cfg, nil
}

// splitList parses a comma-separated value, trimming whitespace and dropping blanks.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Mask renders a secret for display: last 4 chars, or "(not set)" when empty.
func Mask(secret string) string {
	if secret == "" {
		return "(not set)"
	}
	if len(secret) <= 4 {
		return "••••"
	}
	return "••••" + secret[len(secret)-4:]
}
