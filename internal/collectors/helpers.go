package collectors

import (
	"openticollect/internal/matcher"
	"openticollect/internal/models"
)

// scanText runs the matcher over text and builds a Finding for every keyword hit.
// This is the shared path every collector uses to produce findings.
func scanText(source, sourceURL, text, raw string, m *matcher.Matcher) []models.Finding {
	var out []models.Finding
	for _, hit := range m.Match(text) {
		out = append(out, models.Finding{
			Source:         source,
			SourceURL:      sourceURL,
			MatchedKeyword: hit.Keyword.Value,
			Severity:       hit.Keyword.Severity,
			Excerpt:        matcher.Excerpt(text, hit.Index, len(hit.Keyword.Value)),
			Raw:            raw,
			Hash:           models.HashFinding(source, sourceURL, hit.Keyword.Value),
			Status:         "new",
		})
	}
	return out
}
