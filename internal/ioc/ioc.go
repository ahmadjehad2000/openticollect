// Package ioc extracts structured indicators of compromise — IPs, domains,
// URLs, emails, file hashes, CVE IDs and cryptocurrency addresses — from the
// free text of a finding. It is pure: no I/O, no globals mutated.
package ioc

import (
	"regexp"
	"sort"
	"strings"
)

// Kind is an indicator category. Values are stable: they are persisted and
// emitted in the API and STIX export.
type Kind string

const (
	KindIPv4   Kind = "ipv4"
	KindIPv6   Kind = "ipv6"
	KindDomain Kind = "domain"
	KindURL    Kind = "url"
	KindEmail  Kind = "email"
	KindMD5    Kind = "md5"
	KindSHA1   Kind = "sha1"
	KindSHA256 Kind = "sha256"
	KindCVE    Kind = "cve"
	KindBTC    Kind = "btc"
	KindETH    Kind = "eth"
)

// Indicator is one extracted, normalized indicator.
type Indicator struct {
	Kind  Kind
	Value string
}

var (
	reURL    = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>)\]}]+`)
	reEmail  = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b`)
	reDomain = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reIPv6   = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{1,4}:){3,7}[a-f0-9]{1,4}\b`)
	reMD5    = regexp.MustCompile(`(?i)\b[a-f0-9]{32}\b`)
	reSHA1   = regexp.MustCompile(`(?i)\b[a-f0-9]{40}\b`)
	reSHA256 = regexp.MustCompile(`(?i)\b[a-f0-9]{64}\b`)
	reCVE    = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	reETH    = regexp.MustCompile(`(?i)\b0x[a-f0-9]{40}\b`)
	reBTC    = regexp.MustCompile(`\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`)
)

// fileExts are last labels that look like a domain TLD but are file names.
var fileExts = map[string]bool{
	"php": true, "html": true, "htm": true, "txt": true, "json": true,
	"xml": true, "css": true, "js": true, "png": true, "jpg": true,
	"jpeg": true, "gif": true, "svg": true, "exe": true, "zip": true,
	"pdf": true, "doc": true, "md": true, "csv": true, "go": true,
}

// refang reverses common "defanging" so obfuscated indicators still extract.
func refang(s string) string {
	r := strings.NewReplacer(
		"hxxp", "http", "hXXp", "http", "HXXP", "HTTP",
		"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".",
		"[:]", ":", "[at]", "@", "(at)", "@",
	)
	return r.Replace(s)
}

// Extract returns every distinct indicator found in text. Values are
// normalized (lowercased for hosts/hashes/cve; URLs keep their path case)
// and deduplicated. A nil slice is returned when nothing is found.
func Extract(text string) []Indicator {
	text = refang(text)
	seen := map[string]bool{}
	var out []Indicator
	add := func(k Kind, v string) {
		key := string(k) + "\x00" + v
		if v == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Indicator{Kind: k, Value: v})
	}

	urls := reURL.FindAllString(text, -1)
	for _, u := range urls {
		add(KindURL, strings.TrimRight(u, ".,;:!?\"')]}"))
	}
	for _, e := range reEmail.FindAllString(text, -1) {
		add(KindEmail, strings.ToLower(e))
	}
	for _, ip := range reIPv4.FindAllString(text, -1) {
		add(KindIPv4, ip)
	}
	for _, ip := range reIPv6.FindAllString(text, -1) {
		add(KindIPv6, strings.ToLower(ip))
	}
	for _, h := range reSHA256.FindAllString(text, -1) {
		add(KindSHA256, strings.ToLower(h))
	}
	for _, h := range reSHA1.FindAllString(text, -1) {
		add(KindSHA1, strings.ToLower(h))
	}
	for _, h := range reMD5.FindAllString(text, -1) {
		add(KindMD5, strings.ToLower(h))
	}
	for _, c := range reCVE.FindAllString(text, -1) {
		add(KindCVE, strings.ToLower(c))
	}
	for _, a := range reETH.FindAllString(text, -1) {
		add(KindETH, strings.ToLower(a))
	}
	for _, a := range reBTC.FindAllString(text, -1) {
		add(KindBTC, a)
	}
	// Domains last: skip any that is a substring of an extracted email value,
	// and any whose final label is a known file extension.
	for _, d := range reDomain.FindAllString(text, -1) {
		d = strings.ToLower(d)
		labels := strings.Split(d, ".")
		if fileExts[labels[len(labels)-1]] {
			continue
		}
		if isInExtracted(d, out) {
			continue
		}
		add(KindDomain, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// isInExtracted reports whether domain d appears inside an already-extracted
// email value, which would mean emitting it as a bare domain too would
// double-count it. Domains that appear inside a URL are intentionally kept as
// separate indicators and are not suppressed here.
func isInExtracted(d string, out []Indicator) bool {
	for _, in := range out {
		if in.Kind == KindEmail {
			if strings.Contains(strings.ToLower(in.Value), d) {
				return true
			}
		}
	}
	return false
}
