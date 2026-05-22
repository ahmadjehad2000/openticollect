// Package matcher scans text for watchlist keyword hits. Regex keywords are
// compiled once at construction; literals match after Unicode folding (case,
// full-width forms, and common Cyrillic/Greek homoglyphs).
package matcher

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"openticollect/internal/models"
)

const maxExcerpt = 2048

// Hit is a single keyword match within a piece of text.
type Hit struct {
	Keyword models.Keyword
	Index   int // byte offset of the match in the scanned text
}

type Matcher struct {
	literals []foldedLiteral
	regexes  []compiledRegex
}

// foldedLiteral pairs a keyword with its folded, lowercased form.
type foldedLiteral struct {
	keyword models.Keyword
	folded  string
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
			m.literals = append(m.literals, foldedLiteral{
				keyword: k, folded: fold(k.Value),
			})
		}
	}
	return m
}

// Match returns every keyword hit in text. Literal keywords match whole words
// only — after Unicode folding (case + full-width + common homoglyphs) — so a
// keyword never matches as a fragment of a larger word, and one keyword never
// matches inside another (e.g. "acme" will not hit "acmecorp", and "book" will
// not hit "facebook"). Regex keywords are matched against the raw text
// unchanged — a regex keyword owns its own boundary rules.
func (m *Matcher) Match(text string) []Hit {
	var hits []Hit
	folded, offsets := foldIndexed(text)
	for _, lk := range m.literals {
		if lk.folded == "" {
			continue
		}
		if idx := indexWholeWord(folded, lk.folded); idx >= 0 {
			hits = append(hits, Hit{Keyword: lk.keyword, Index: offsets[idx]})
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

// indexWholeWord returns the byte offset of the first whole-word occurrence of
// sub within s, or -1 when there is none. An occurrence is a whole word when
// the runes immediately before and after it are not alphanumeric (the start
// and end of the string also count as boundaries). This keeps a literal
// keyword from matching as a fragment of a larger word.
//
// Non-alphanumeric characters inside sub itself (e.g. the dot in "acme.com")
// are matched literally — only the two edges of the occurrence are checked.
func indexWholeWord(s, sub string) int {
	if sub == "" {
		return -1
	}
	for from := 0; from <= len(s)-len(sub); {
		i := strings.Index(s[from:], sub)
		if i < 0 {
			return -1
		}
		at := from + i
		if !wordRuneBefore(s, at) && !wordRuneAfter(s, at+len(sub)) {
			return at
		}
		from = at + 1
	}
	return -1
}

// wordRuneBefore reports whether the rune ending just before byte offset at is
// alphanumeric. A string-start (at <= 0) is treated as a boundary (false).
func wordRuneBefore(s string, at int) bool {
	if at <= 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:at])
	return isWordRune(r)
}

// wordRuneAfter reports whether the rune starting at byte offset end is
// alphanumeric. A string-end (end >= len) is treated as a boundary (false).
func wordRuneAfter(s string, end int) bool {
	if end >= len(s) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s[end:])
	return isWordRune(r)
}

// isWordRune reports whether r is a letter or digit — the character class that
// defines a "word" for whole-word matching.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// confusables maps common Cyrillic/Greek homoglyphs to their Latin look-alike.
// Keys are lowercase; foldRune lowercases before lookup.
var confusables = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
	'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ɡ': 'g',
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ν': 'v',
	'τ': 't', 'κ': 'k', 'ι': 'i', 'υ': 'u', 'χ': 'x',
}

// foldRune normalizes one rune: full-width ASCII forms collapse to ASCII, and
// known homoglyphs collapse to their Latin look-alike.
func foldRune(r rune) rune {
	if r >= 0xFF01 && r <= 0xFF5E { // full-width '!'..'~'
		r -= 0xFEE0
	}
	if c, ok := confusables[r]; ok {
		return c
	}
	return r
}

// fold lowercases and normalizes s for literal matching.
func fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldRune(unicode.ToLower(r)))
	}
	return b.String()
}

// foldIndexed folds s and returns the folded string plus a per-byte map back
// to the original byte offset, so a match index in the folded string can be
// translated to an offset in the original text for excerpting.
func foldIndexed(s string) (string, []int) {
	var b strings.Builder
	b.Grow(len(s))
	offsets := make([]int, 0, len(s))
	for i, r := range s {
		start := b.Len()
		b.WriteRune(foldRune(unicode.ToLower(r)))
		for j := start; j < b.Len(); j++ {
			offsets = append(offsets, i)
		}
	}
	return b.String(), offsets
}
