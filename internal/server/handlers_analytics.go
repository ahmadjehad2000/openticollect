package server

import (
	"net/http"

	"openticollect/internal/store"
)

const (
	chartBarH   = 22  // px per bar row
	chartBarMax = 440 // px width of the longest bar
)

type chartBar struct {
	Label string
	Count int
	Y     int // top of the bar row
	W     int // bar width in px
	TextY int // baseline for centred text
}

type chartView struct {
	Title  string
	Empty  string
	Bars   []chartBar
	Height int
}

type analyticsData struct {
	Daily    chartView
	BySource chartView
	ByKind   chartView
	Err      string
}

// makeChart scales a set of counts into SVG bar geometry.
func makeChart(title, empty string, counts []store.Count) chartView {
	cv := chartView{Title: title, Empty: empty}
	max := 0
	for _, c := range counts {
		if c.Count > max {
			max = c.Count
		}
	}
	for i, c := range counts {
		w := 0
		if max > 0 {
			w = c.Count * chartBarMax / max
		}
		if w < 2 && c.Count > 0 {
			w = 2
		}
		y := i * chartBarH
		cv.Bars = append(cv.Bars, chartBar{
			Label: c.Label, Count: c.Count, Y: y, W: w, TextY: y + chartBarH/2 + 4,
		})
	}
	cv.Height = len(cv.Bars) * chartBarH
	if cv.Height == 0 {
		cv.Height = chartBarH
	}
	return cv
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	var d analyticsData
	daily, err := s.store.FindingsPerDay(30)
	if err != nil {
		d.Err = "Failed to load analytics: " + err.Error()
		s.render(w, "analytics", pageData{Nav: "analytics", Title: "Analytics",
			Heading: "Analytics", Description: "Collection activity and yield.", Data: d})
		return
	}
	bySource, _ := s.store.FindingsBySource()
	byKind, _ := s.store.IndicatorsByKind()
	d.Daily = makeChart("Findings per day (last 30 days)", "No findings yet.", daily)
	d.BySource = makeChart("Findings by source", "No findings yet.", bySource)
	d.ByKind = makeChart("Extracted indicators by type", "No indicators yet.", byKind)
	s.render(w, "analytics", pageData{
		Nav: "analytics", Title: "Analytics", Heading: "Analytics",
		Description: "Collection activity, source yield, and indicator mix.", Data: d,
	})
}
