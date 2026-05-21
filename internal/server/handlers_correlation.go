package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"openticollect/internal/models"
)

type correlationData struct {
	Rules []models.CorrelationRule
	Err   string
}

func (s *Server) handleCorrelation(w http.ResponseWriter, r *http.Request) {
	var d correlationData
	rules, err := s.store.ListCorrelationRules()
	if err != nil {
		d.Err = "Failed to load correlation rules: " + err.Error()
	}
	d.Rules = rules
	s.render(w, "correlation", pageData{
		Nav: "correlation", Title: "Correlation", Heading: "Correlation",
		Description: "Smart correlation runs by default; add custom rules for precise alerting.",
		Data:        d,
	})
}

func (s *Server) handleCorrelationRuleAdd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	minSources := atoiDefault(r.FormValue("min_sources"), 0)
	minCount := atoiDefault(r.FormValue("min_count"), 0)
	window := atoiDefault(r.FormValue("window_minutes"), 0)

	_, err := s.store.CreateCorrelationRule(
		strings.TrimSpace(r.FormValue("name")),
		strings.TrimSpace(r.FormValue("keyword")),
		minSources, minCount, window, r.FormValue("severity"))
	if err != nil {
		w.Write([]byte(`<div class="error-banner">` +
			template.HTMLEscapeString(err.Error()) + `</div>`))
		return
	}
	w.Header().Set("HX-Redirect", "/correlation")
}

func (s *Server) handleCorrelationRuleToggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	rule, err := s.correlationRuleByID(id)
	if err != nil {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	if err := s.store.SetCorrelationRuleEnabled(id, !rule.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rule.Enabled = !rule.Enabled
	s.renderPartial(w, "rule_row", rule)
}

func (s *Server) handleCorrelationRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteCorrelationRule(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Empty 200: the htmx outerHTML swap removes the row.
}

func (s *Server) correlationRuleByID(id int64) (models.CorrelationRule, error) {
	rules, err := s.store.ListCorrelationRules()
	if err != nil {
		return models.CorrelationRule{}, err
	}
	for _, r := range rules {
		if r.ID == id {
			return r, nil
		}
	}
	return models.CorrelationRule{}, fmt.Errorf("correlation rule %d not found", id)
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
