package collectors

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/matcher"
	"openticollect/internal/models"
)

// secretPattern is one named credential/secret detector.
type secretPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns are high-signal detectors for credentials commonly leaked in
// public content. Generic patterns are deliberately last and broadest.
var secretPatterns = []secretPattern{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`github_pat_[0-9A-Za-z_]{60,}`)},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"Slack webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}`)},
	{"Stripe secret key", regexp.MustCompile(`sk_live_[0-9A-Za-z]{20,}`)},
	{"private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"JSON Web Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"generic API credential", regexp.MustCompile(
		`(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["' ]{0,3}[:=]["' ]{0,3}[0-9A-Za-z._\-]{16,}`)},
}

// SecretScanner scrapes the URLs in SECRETSCAN_URLS and flags exposed secrets.
// A secret found on a page that also mentions a watchlist keyword is escalated
// to critical — a credential leaking alongside a watched asset.
type SecretScanner struct {
	urls         []string
	pause        time.Duration
	maxPerSource int
}

func NewSecretScanner(cfg *config.Config) *SecretScanner {
	return &SecretScanner{
		urls:         cfg.SecretScanURLs,
		pause:        300 * time.Millisecond,
		maxPerSource: 50,
	}
}

func (s *SecretScanner) Name() string            { return "secretscanner" }
func (s *SecretScanner) Interval() time.Duration { return 30 * time.Minute }

func (s *SecretScanner) MissingEnv(cfg *config.Config) []string {
	if len(cfg.SecretScanURLs) == 0 {
		return []string{"SECRETSCAN_URLS"}
	}
	return nil
}

func (s *SecretScanner) Enabled(cfg *config.Config) bool { return len(s.MissingEnv(cfg)) == 0 }

func (s *SecretScanner) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result
	attempted, succeeded := 0, 0

	for _, u := range s.urls {
		if attempted > 0 {
			pacePause(ctx, s.pause)
		}
		attempted++
		body, err := fetchText(ctx, in.HTTP, u, nil)
		if err != nil {
			in.Logger.Warn("secretscanner: fetch failed", "url", u, "err", err)
			continue
		}
		succeeded++
		res.ItemsFetched++
		res.Findings = append(res.Findings, s.scan(u, body, m.Match(body))...)
	}
	if attempted > 0 && succeeded == 0 {
		return res, fmt.Errorf("secretscanner: all %d fetches failed", attempted)
	}
	return res, nil
}

// scan runs every secret detector over one page's raw body.
func (s *SecretScanner) scan(pageURL, body string, hits []matcher.Hit) []models.Finding {
	var out []models.Finding
	seen := map[string]bool{}

	// Co-presence of a watchlist keyword ties the secret to a watched asset.
	keyword := ""
	if len(hits) > 0 {
		keyword = hits[0].Keyword.Value
	}

	for _, pat := range secretPatterns {
		for _, match := range pat.re.FindAllString(body, -1) {
			snippet := maskSecret(match)
			if strings.Contains(pat.name, "private key") {
				snippet = "key block present"
			}
			dedup := pat.name + "|" + snippet
			if seen[dedup] {
				continue
			}
			seen[dedup] = true

			f := models.Finding{
				Source:    "secretscanner",
				SourceURL: pageURL,
				Status:    "new",
				Hash:      models.HashFinding("secretscanner", pageURL, dedup),
			}
			if keyword != "" {
				f.MatchedKeyword = keyword
				f.Severity = "critical"
				f.Excerpt = fmt.Sprintf(
					"Possible %s exposed (%s) on a page that also mentions watched keyword %q.",
					pat.name, snippet, keyword)
			} else {
				f.MatchedKeyword = pat.name
				f.Severity = "warn"
				f.Excerpt = fmt.Sprintf("Possible %s exposed (%s).", pat.name, snippet)
			}
			out = append(out, f)
			if len(out) >= s.maxPerSource {
				return out
			}
		}
	}
	return out
}

// maskSecret redacts the middle of a detected secret for safe display.
func maskSecret(s string) string {
	switch {
	case len(s) <= 2:
		return "••••"
	case len(s) <= 10:
		return s[:2] + "••••"
	default:
		return s[:4] + "••••••" + s[len(s)-4:]
	}
}
