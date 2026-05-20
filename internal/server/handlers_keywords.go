package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"openticollect/internal/models"
)

type keywordsData struct {
	Keywords []models.Keyword
	Err      string
}

func (s *Server) handleKeywords(w http.ResponseWriter, r *http.Request) {
	var d keywordsData
	kws, err := s.store.ListKeywords()
	if err != nil {
		d.Err = "Failed to load keywords: " + err.Error()
	}
	d.Keywords = kws
	s.render(w, "keywords", pageData{
		Nav: "keywords", Title: "Keywords", Heading: "Keywords",
		Description: "Watchlist of literals and regexes.", Data: d,
	})
}

func (s *Server) handleKeywordAdd(w http.ResponseWriter, r *http.Request) {
	value := strings.TrimSpace(r.FormValue("value"))
	kind := r.FormValue("kind")
	severity := r.FormValue("severity")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := s.store.CreateKeyword(value, kind, severity); err != nil {
		w.Write([]byte(`<div class="error-banner">` +
			template.HTMLEscapeString(err.Error()) + `</div>`))
		return
	}
	// Full reload so the form clears and the new row appears.
	w.Header().Set("HX-Redirect", "/keywords")
}

func (s *Server) handleKeywordToggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	kw, err := s.keywordByID(id)
	if err != nil {
		http.Error(w, "keyword not found", http.StatusNotFound)
		return
	}
	if err := s.store.SetKeywordEnabled(id, !kw.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	kw.Enabled = !kw.Enabled
	s.renderPartial(w, "keyword_row", kw)
}

func (s *Server) handleKeywordDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteKeyword(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Empty 200 body: the htmx outerHTML swap removes the row.
}

func (s *Server) keywordByID(id int64) (models.Keyword, error) {
	kws, err := s.store.ListKeywords()
	if err != nil {
		return models.Keyword{}, err
	}
	for _, k := range kws {
		if k.ID == id {
			return k, nil
		}
	}
	return models.Keyword{}, fmt.Errorf("keyword %d not found", id)
}
