package ioc

import (
	"net/url"
	"regexp"
	"strings"
)

// Credential is a leaked-credential record. The password is NEVER stored —
// only a redacted shape is kept, enough to gauge strength without exposure.
type Credential struct {
	Service  string // affected host/domain, lowercased; "" if unknown
	Username string // username or email local+domain
	Masked   string // redacted password shape, e.g. "S••••3 (14)"
}

var (
	reCredURLLine   = regexp.MustCompile(`(?i)^(https?://[^\s:]+(?::\d+)?[^\s:]*):([^\s:]{1,128}):(\S{1,256})$`)
	reCredEmailLine = regexp.MustCompile(`(?i)^([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}):(\S{1,256})$`)
	reCredUserLine  = regexp.MustCompile(`^([A-Za-z0-9._\-]{3,64}):(\S{1,256})$`)
)

// ExtractCredentials scans text line by line for credential-dump layouts:
// `email:password`, `url:login:password` (stealer-log), and `user:password`.
// Passwords are immediately reduced to a masked shape.
func ExtractCredentials(text string) []Credential {
	var out []Credential
	seen := map[string]bool{}
	emit := func(service, user, pass string) {
		key := strings.ToLower(service + "|" + user)
		if user == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Credential{
			Service:  strings.ToLower(service),
			Username: user,
			Masked:   maskPassword(pass),
		})
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || len(line) > 400 {
			continue
		}
		if m := reCredURLLine.FindStringSubmatch(line); m != nil {
			emit(hostOf(m[1]), m[2], m[3])
			continue
		}
		if m := reCredEmailLine.FindStringSubmatch(line); m != nil {
			emit(domainOfEmail(m[1]), m[1], m[2])
			continue
		}
		if m := reCredUserLine.FindStringSubmatch(line); m != nil {
			// Reject pairs that are actually a bare "word:word" sentence
			// fragment: require the value to look password-like.
			if looksLikePassword(m[2]) {
				emit("", m[1], m[2])
			}
		}
	}
	return out
}

// CredentialServices returns the distinct, non-empty service domains across a
// set of credentials — used to match leaks against the brand watchlist.
func CredentialServices(creds []Credential) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range creds {
		if c.Service != "" && !seen[c.Service] {
			seen[c.Service] = true
			out = append(out, c.Service)
		}
	}
	return out
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func domainOfEmail(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		return strings.ToLower(email[i+1:])
	}
	return ""
}

// looksLikePassword filters out plain `word:word` text: a password-like value
// has mixed character classes or is reasonably long.
func looksLikePassword(s string) bool {
	if len(s) < 6 {
		return false
	}
	var hasDigit, hasUpper, hasLower, hasSym bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		default:
			hasSym = true
		}
	}
	classes := 0
	for _, b := range []bool{hasDigit, hasUpper, hasLower, hasSym} {
		if b {
			classes++
		}
	}
	return classes >= 2 || len(s) >= 12
}

// maskPassword renders a password as first char + bullets + last char + length,
// never returning the original. An empty input yields "(empty)".
func maskPassword(p string) string {
	r := []rune(p)
	switch {
	case len(r) == 0:
		return "(empty)"
	case len(r) <= 2:
		return "•• (" + itoa(len(r)) + ")"
	default:
		return string(r[0]) + "••••" + string(r[len(r)-1]) + " (" + itoa(len(r)) + ")"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
