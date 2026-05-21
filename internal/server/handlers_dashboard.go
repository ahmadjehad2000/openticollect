package server

import (
	"net/http"
	"time"

	"openticollect/internal/models"
	"openticollect/internal/store"
)

type dashboardData struct {
	KPIs     kpiData
	Recent   []models.Finding
	Activity []activityItem
	Err      string
}

type kpiData struct {
	TotalFindings int
	Last24h       int
	ActiveSources int
	WatchlistSize int
}

type activityItem struct {
	Name    string
	HasRun  bool
	OK      bool
	LastRun *time.Time
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	var d dashboardData

	total, err := s.store.CountFindings()
	if err != nil {
		d.Err = "Failed to load dashboard: " + err.Error()
		s.renderDashboard(w, d)
		return
	}
	d.KPIs.TotalFindings = total
	if n, err := s.store.CountFindingsSince24h(); err == nil {
		d.KPIs.Last24h = n
	}
	if kws, err := s.store.ListKeywords(); err == nil {
		d.KPIs.WatchlistSize = len(kws)
	}
	if recent, _, err := s.store.ListFindings(store.FindingFilter{
		Statuses: []string{"new"}, Limit: 25,
	}); err == nil {
		d.Recent = recent
	}

	for _, c := range s.cols {
		item := activityItem{Name: c.Name()}
		enabled, _ := s.store.SourceEnabled(c.Name())
		if c.Enabled(s.cfg) && enabled {
			d.KPIs.ActiveSources++
		}
		if run, err := s.store.LatestRun(c.Name()); err == nil && run != nil {
			item.HasRun = true
			item.OK = run.OK
			item.LastRun = run.FinishedAt
			if item.LastRun == nil {
				item.LastRun = &run.StartedAt
			}
		}
		d.Activity = append(d.Activity, item)
	}
	s.renderDashboard(w, d)
}

func (s *Server) renderDashboard(w http.ResponseWriter, d dashboardData) {
	s.render(w, "dashboard", pageData{
		Nav: "", Title: "Dashboard", Heading: "Dashboard",
		Description: "Overview of collection activity.", Data: d,
	})
}
