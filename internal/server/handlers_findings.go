package server

import "net/http"

// Stubs filled in by P3 Task 6.

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	s.render(w, "findings", pageData{
		Nav: "findings", Title: "Findings", Heading: "Findings",
		Description: "Keyword matches across all sources.",
	})
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleFindingResend(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
