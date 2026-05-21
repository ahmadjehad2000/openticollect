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
	BasePath   string // "/findings" or "/archive"
	RefreshURL string // current view URL, for the refresh button
	Poll       bool   // auto-refresh is on
	PollURL    string // URL that flips the auto-refresh state
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

// handleFindings lists active (status=new) findings.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	s.findingList(w, r, "/findings", "findings", "Findings",
		"Active keyword matches across all sources.", []string{"new"})
}

// handleArchive lists reviewed and suppressed findings.
func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request) {
	s.findingList(w, r, "/archive", "archive", "Archive",
		"Findings you have reviewed or suppressed.", []string{"reviewed", "suppressed"})
}

func (s *Server) findingList(w http.ResponseWriter, r *http.Request,
	base, nav, heading, desc string, statuses []string) {
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
		Statuses: statuses,
		Limit:    findingsPerPage,
		Offset:   (page - 1) * findingsPerPage,
	}

	poll := q.Get("poll") == "on"
	d := findingsData{
		Filter:     filterState{Search: filter.Search, Severity: filter.Severity},
		BasePath:   base,
		RefreshURL: r.URL.RequestURI(),
		Poll:       poll,
		PollURL:    pollURL(base, q, !poll),
		Page:       page,
	}
	for _, c := range s.cols {
		d.Sources = append(d.Sources, sourceCheck{Name: c.Name(), Checked: contains(selected, c.Name())})
	}

	render := func() {
		s.render(w, "findings", pageData{
			Nav: nav, Title: heading, Heading: heading, Description: desc, Data: d,
		})
	}

	findings, total, err := s.store.ListFindings(filter)
	if err != nil {
		d.Err = "Failed to load findings: " + err.Error()
		render()
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
	d.PrevURL = pageURL(base, q, page-1)
	d.NextURL = pageURL(base, q, page+1)
	render()
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

// handleFindingStatus changes a finding's status. Because the change moves the
// finding between the Findings and Archive lists, the response removes the row
// from the current view and clears the detail panel.
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<div id="finding-panel" hx-swap-oob="true"></div>`))
}

// handleFindingsBulk applies one status change to every selected finding.
func (s *Server) handleFindingsBulk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	if action != "new" && action != "reviewed" && action != "suppressed" {
		http.Error(w, "bad action", http.StatusBadRequest)
		return
	}
	for _, idStr := range r.PostForm["id"] {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}
		if err := s.store.SetFindingStatus(id, action); err != nil {
			s.log.Warn("server: bulk status update failed", "id", id, "err", err)
		}
	}
	// The affected findings moved between the Findings and Archive lists;
	// reload so the current view reflects it.
	w.Header().Set("HX-Refresh", "true")
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

// pageURL rebuilds base's query with a new page number.
func pageURL(base string, q url.Values, page int) string {
	c := url.Values{}
	for k, v := range q {
		if k != "page" {
			c[k] = v
		}
	}
	c.Set("page", strconv.Itoa(page))
	return base + "?" + c.Encode()
}

// pollURL rebuilds base's query with auto-refresh polling set on or off.
func pollURL(base string, q url.Values, on bool) string {
	c := url.Values{}
	for k, v := range q {
		if k != "poll" {
			c[k] = v
		}
	}
	if on {
		c.Set("poll", "on")
	} else {
		c.Set("poll", "off")
	}
	return base + "?" + c.Encode()
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
