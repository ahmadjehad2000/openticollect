package server

import "net/http"

// Stubs filled in by P3 Task 7.

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	s.render(w, "sources", pageData{
		Nav: "sources", Title: "Sources", Heading: "Sources",
		Description: "Collector status and scheduling.",
	})
}

func (s *Server) handleSourceToggle(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
