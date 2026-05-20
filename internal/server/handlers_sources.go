package server

import (
	"net/http"

	"openticollect/internal/collectors"
	"openticollect/internal/models"
)

type sourcesData struct {
	Sources []models.SourceStatus
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	var d sourcesData
	for _, c := range s.cols {
		d.Sources = append(d.Sources, s.collectorStatus(c))
	}
	s.render(w, "sources", pageData{
		Nav: "sources", Title: "Sources", Heading: "Sources",
		Description: "Collector status and scheduling.", Data: d,
	})
}

func (s *Server) handleSourceToggle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	col := s.collectorByName(name)
	if col == nil {
		http.Error(w, "unknown source", http.StatusNotFound)
		return
	}
	if !col.Enabled(s.cfg) {
		http.Error(w, "source is misconfigured", http.StatusBadRequest)
		return
	}
	enabled, err := s.store.SourceEnabled(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.store.SetSourceEnabled(name, !enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderPartial(w, "source_row", s.collectorStatus(col))
}

// collectorStatus assembles the /sources view model for one collector.
func (s *Server) collectorStatus(c collectors.Collector) models.SourceStatus {
	st := models.SourceStatus{Name: c.Name()}
	enabled, _ := s.store.SourceEnabled(c.Name())
	switch {
	case !c.Enabled(s.cfg):
		st.Status = "misconfigured"
		st.MissingEnv = c.MissingEnv(s.cfg)
	case !enabled:
		st.Status = "disabled"
	default:
		st.Status = "enabled"
	}
	if run, err := s.store.LatestRun(c.Name()); err == nil && run != nil {
		st.LastError = run.Error
		if run.FinishedAt != nil {
			st.LastRun = run.FinishedAt
		} else {
			st.LastRun = &run.StartedAt
		}
	}
	if t, ok := s.sched.NextRun(c.Name()); ok {
		st.NextRun = &t
	}
	return st
}

func (s *Server) collectorByName(name string) collectors.Collector {
	for _, c := range s.cols {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
