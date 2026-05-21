package server

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

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
	if rate, runs, err := s.store.SourceHealth(c.Name(), 20); err == nil {
		st.SuccessRate = rate
		st.Runs = runs
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

// handleSourceTest runs one collector on demand and reports the outcome — used
// to verify an API key or a source's reachability from the Sources page.
func (s *Server) handleSourceTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	col := s.collectorByName(r.PathValue("name"))
	if col == nil {
		w.Write([]byte(`<span class="status-err">unknown source</span>`))
		return
	}
	if !col.Enabled(s.cfg) {
		w.Write([]byte(`<span class="status-err">misconfigured — needs ` +
			template.HTMLEscapeString(strings.Join(col.MissingEnv(s.cfg), ", ")) + `</span>`))
		return
	}
	keywords, err := s.store.EnabledKeywords()
	if err != nil {
		w.Write([]byte(`<span class="status-err">` +
			template.HTMLEscapeString(err.Error()) + `</span>`))
		return
	}

	var tor *http.Client
	if s.cfg.TorProxy != "" {
		if tc, terr := collectors.TorClient(s.cfg.TorProxy); terr == nil {
			tor = tc
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	res, runErr := col.Run(ctx, collectors.Input{
		Keywords: keywords,
		HTTP:     collectors.DefaultHTTPClient(),
		Tor:      tor,
		Logger:   s.log,
	})
	if runErr != nil {
		w.Write([]byte(`<span class="status-err">failed: ` +
			template.HTMLEscapeString(runErr.Error()) + `</span>`))
		return
	}
	w.Write([]byte(fmt.Sprintf(
		`<span class="status-ok">ok — %d items fetched, %d matches</span>`,
		res.ItemsFetched, len(res.Findings))))
}
