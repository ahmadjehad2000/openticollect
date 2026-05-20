package collectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"openticollect/internal/config"
	"openticollect/internal/matcher"
	"openticollect/internal/models"
)

// HIBP collects the public Have I Been Pwned breach catalog and checks any
// SHA-1-hash keywords against the Pwned Passwords k-anonymity range API.
type HIBP struct {
	breachesURL string
	pwnedURL    string
}

func NewHIBP(cfg *config.Config) *HIBP {
	return &HIBP{
		breachesURL: "https://haveibeenpwned.com",
		pwnedURL:    "https://api.pwnedpasswords.com",
	}
}

func (h *HIBP) Name() string                          { return "hibp" }
func (h *HIBP) Interval() time.Duration                { return 6 * time.Hour }
func (h *HIBP) MissingEnv(cfg *config.Config) []string { return nil } // keyless
func (h *HIBP) Enabled(cfg *config.Config) bool        { return true }

var sha1Hash = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func (h *HIBP) Run(ctx context.Context, in Input) (Result, error) {
	m := matcher.New(in.Keywords)
	var res Result
	ok := 0

	var breaches []struct {
		Name        string `json:"Name"`
		Title       string `json:"Title"`
		Domain      string `json:"Domain"`
		Description string `json:"Description"`
	}
	if err := fetchJSON(ctx, in.HTTP, http.MethodGet,
		h.breachesURL+"/api/v3/breaches", nil, nil, &breaches); err != nil {
		in.Logger.Warn("hibp: breach catalog failed", "err", err)
	} else {
		ok++
		for _, b := range breaches {
			res.ItemsFetched++
			text := b.Name + "\n" + b.Title + "\n" + b.Domain + "\n" + b.Description
			res.Findings = append(res.Findings,
				scanText("hibp", h.breachesURL+"/PwnedWebsites", text, "", m)...)
		}
	}

	for _, kw := range in.Keywords {
		if !kw.Enabled || !sha1Hash.MatchString(kw.Value) {
			continue
		}
		hash := strings.ToUpper(kw.Value)
		body, err := fetchText(ctx, in.HTTP, h.pwnedURL+"/range/"+hash[:5], nil)
		if err != nil {
			in.Logger.Warn("hibp: pwned passwords lookup failed", "err", err)
			continue
		}
		ok++
		res.ItemsFetched++
		if count := pwnedCount(body, hash[5:]); count > 0 {
			res.Findings = append(res.Findings, models.Finding{
				Source:         "hibp",
				SourceURL:      "https://haveibeenpwned.com/Passwords",
				MatchedKeyword: kw.Value,
				Severity:       kw.Severity,
				Excerpt:        fmt.Sprintf("Password hash %s seen %d times in breaches.", kw.Value, count),
				Hash:           models.HashFinding("hibp", "pwned-password", kw.Value),
				Status:         "new",
			})
		}
	}

	if ok == 0 {
		return res, fmt.Errorf("hibp: all lookups failed")
	}
	return res, nil
}

// pwnedCount returns the breach count for a SHA-1 suffix within a range response.
func pwnedCount(body, suffix string) int {
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
			n, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			return n
		}
	}
	return 0
}
