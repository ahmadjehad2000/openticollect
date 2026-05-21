package server

import "html/template"

// icons is the vendored inline-SVG set: stroke 1.5px, currentColor, no library.
var icons = map[string]template.HTML{
	"eye":      svg(`<path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/>`),
	"alert":    svg(`<path d="M12 2 2 21h20L12 2z"/><line x1="12" y1="9" x2="12" y2="14"/><line x1="12" y1="17.4" x2="12" y2="17.5"/>`),
	"check":    svg(`<polyline points="20 6 9 17 4 12"/>`),
	"x":        svg(`<line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/>`),
	"refresh":  svg(`<path d="M21 12a9 9 0 1 1-3-6.7"/><polyline points="21 3 21 9 15 9"/>`),
	"settings": svg(`<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>`),
	"search":   svg(`<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16" y2="16"/>`),
	"external": svg(`<path d="M14 4h6v6"/><path d="M20 4 9 15"/><path d="M19 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5"/>`),
}

func svg(body string) template.HTML {
	return template.HTML(`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" ` +
		`stroke="currentColor" stroke-width="1.5" stroke-linecap="round" ` +
		`stroke-linejoin="round" aria-hidden="true">` + body + `</svg>`)
}

// icon returns the named inline SVG, or empty if unknown.
func icon(name string) template.HTML { return icons[name] }
