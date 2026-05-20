// Package matcher scans text for watchlist keyword hits. Regex keywords are
// compiled once at construction; literals match case-insensitively.
package matcher

import (
	"regexp"
	"strings"

	"openticollect/internal/models"
)

const maxExcerpt = 2048

// Hit is a single keyword match within a piece of text.
type Hit struct {
	Keyword models.Keyword
	Index   int // byte offset of the match in the scanned text
}

type Matcher struct {
	literals []models.Keyword
	regexes  []compiledRegex
}

type compiledRegex struct {
	keyword models.Keyword
	re      *regexp.Regexp
}

// New builds a Matcher. Disabled keywords and regexes that fail to compile are
// silently dropped — a bad regex is never fatal.
func New(keywords []models.Keyword) *Matcher {
	m := &Matcher{}
	for _, k := range keywords {
		if !k.Enabled {
			continue
		}
		switch k.Kind {
		case "regex":
			re, err := regexp.Compile(k.Value)
			if err != nil {
				continue
			}
			m.regexes = append(m.regexes, compiledRegex{keyword: k, re: re})
		default: // "literal"
			m.literals = append(m.literals, k)
		}
	}
	return m
}

// Match returns every keyword hit in text (one Hit per matching keyword).
func (m *Matcher) Match(text string) []Hit {
	var hits []Hit
	lower := strings.ToLower(text)
	for _, k := range m.literals {
		if idx := strings.Index(lower, strings.ToLower(k.Value)); idx >= 0 {
			hits = append(hits, Hit{Keyword: k, Index: idx})
		}
	}
	for _, cr := range m.regexes {
		if loc := cr.re.FindStringIndex(text); loc != nil {
			hits = append(hits, Hit{Keyword: cr.keyword, Index: loc[0]})
		}
	}
	return hits
}

// Excerpt returns a context window around a match, capped at maxExcerpt bytes.
func Excerpt(text string, at, length int) string {
	pad := (maxExcerpt - length) / 2
	if pad < 0 {
		pad = 0
	}
	start := at - pad
	if start < 0 {
		start = 0
	}
	end := at + length + pad
	if end > len(text) {
		end = len(text)
	}
	ex := text[start:end]
	if len(ex) > maxExcerpt {
		ex = ex[:maxExcerpt]
	}
	return ex
}
