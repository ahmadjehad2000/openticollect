package server

import "net/http"

// Stubs filled in by P3 Task 8.

func (s *Server) handleKeywords(w http.ResponseWriter, r *http.Request) {
	s.render(w, "keywords", pageData{
		Nav: "keywords", Title: "Keywords", Heading: "Keywords",
		Description: "Watchlist of literals and regexes.",
	})
}

func (s *Server) handleKeywordAdd(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleKeywordToggle(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleKeywordDelete(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
