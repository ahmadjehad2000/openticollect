package correlation

import (
	"fmt"
	"sort"
	"time"

	"openticollect/internal/models"
)

// iocCorrelate raises an alert when one extracted indicator value appears in
// findings from >= 2 distinct collector sources inside the smart window. It
// reuses the shared group/evidence helpers so alerts stay evidence-backed.
func iocCorrelate(findings []models.Finding,
	iocs map[int64][]models.Indicator, now time.Time) []Alert {
	if len(findings) == 0 || len(iocs) == 0 {
		return nil
	}
	cutoff := now.Add(-smartWindow)
	kinds := map[string]string{} // indicator value -> kind
	groups := map[string]*group{}
	for _, f := range findings {
		if f.Source == Source {
			continue
		}
		if !f.CreatedAt.IsZero() && f.CreatedAt.Before(cutoff) {
			continue
		}
		for _, in := range iocs[f.ID] {
			g := groups[in.Value]
			if g == nil {
				g = &group{keyword: in.Value, sources: map[string]bool{}, urls: map[string]string{}}
				groups[in.Value] = g
				kinds[in.Value] = in.Kind
			}
			g.sources[f.Source] = true
			if f.SourceURL != "" && g.urls[f.Source] == "" {
				g.urls[f.Source] = f.SourceURL
			}
			g.count++
			if rank := models.SeverityRank(f.Severity); rank > g.maxSev {
				g.maxSev = rank
			}
		}
	}
	values := make([]string, 0, len(groups))
	for v := range groups {
		values = append(values, v)
	}
	sort.Strings(values)

	var alerts []Alert
	for _, v := range values {
		g := groups[v]
		if len(g.sources) < 2 {
			continue
		}
		ev, primary := evidence(g)
		alerts = append(alerts, Alert{
			Engine:   "smart",
			Rule:     "ioc-correlation",
			Keyword:  v,
			Severity: sevName(g.maxSev),
			Summary: fmt.Sprintf("IOC correlation: %s %q seen across %s within 24h. Evidence — %s",
				kinds[v], v, plural(len(g.sources), "source"), evidenceText(ev)),
			Evidence:   ev,
			PrimaryURL: primary,
		})
	}
	return alerts
}
