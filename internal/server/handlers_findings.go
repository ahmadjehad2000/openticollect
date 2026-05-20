package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"openticollect/internal/models"
	"openticollect/internal/notifier"
	"openticollect/internal/store"
)

const findingsPerPage = 50

type findingsData struct {
	Findings   []models.Finding
	Filter     filterState
	Sources    []sourceCheck
	Page       int
	TotalPages int
	Total      int
	HasPrev    bool
	HasNext    bool
	PrevURL    string
	NextURL    string
	Err        string
}

type filterState struct{ Search, Severity string }

type sourceCheck struct {
	Name    string
	Checked bool
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := 1
	if p, err := strconv.Atoi(q.Get("page")); err == nil && p > 1 {
		page = p
	}
	selected := q["source"]
	filter := store.FindingFilter{
		Sources:  selected,
		Severity: q.Get("severity"),
		Search:   strings.TrimSpace(q.Get("q")),
		Limit:    findingsPerPage,
		Offset:   (page - 1) * findingsPerPage,
	}

	d := findingsData{
		Filter: filterState{Search: filter.Search, Severity: filter.Severity},
		Page:   page,
	}
	for _, c := range s.cols {
		d.Sources = append(d.Sources, sourceCheck{Name: c.Name(), Checked: contains(selected, c.Name())})
	}

	findings, total, err := s.store.ListFindings(filter)
	if err != nil {
		d.Err = "Failed to load findings: " + err.Error()
		s.renderFindings(w, d)
		return
	}
	d.Findings = findings
	d.Total = total
	d.TotalPages = (total + findingsPerPage - 1) / findingsPerPage
	if d.TotalPages < 1 {
		d.TotalPages = 1
	}
	d.HasPrev = page > 1
	d.HasNext = page < d.TotalPages
	d.PrevURL = findingsURL(q, page-1)
	d.NextURL = findingsURL(q, page+1)
	s.renderFindings(w, d)
}

func (s *Server) renderFindings(w http.ResponseWriter, d findingsData) {
	s.render(w, "findings", pageData{
		Nav: "findings", Title: "Findings", Heading: "Findings",
		Description: "Keyword matches across all sources.", Data: d,
	})
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	f, err := s.store.GetFinding(id)
	if err != nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	s.renderPartial(w, "finding_panel", f)
}

func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.store.SetFindingStatus(id, r.FormValue("status")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, err := s.store.GetFinding(id)
	if err != nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	s.renderPartial(w, "findings_row", f)
}

func (s *Server) handleFindingResend(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	f, err := s.store.GetFinding(id)
	if err != nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	sinks := s.buildSinks()
	if len(sinks) == 0 {
		w.Write([]byte(`<span class="status-err">No notifiers configured</span>`))
		return
	}
	notifier.New(s.log, sinks...).Dispatch(r.Context(), []models.Finding{f})
	w.Write([]byte(`<span class="status-ok">Alert re-dispatched</span>`))
}

// findingsURL rebuilds the current query with a new page number.
func findingsURL(q url.Values, page int) string {
	c := url.Values{}
	for k, v := range q {
		if k != "page" {
			c[k] = v
		}
	}
	c.Set("page", strconv.Itoa(page))
	return "/findings?" + c.Encode()
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
