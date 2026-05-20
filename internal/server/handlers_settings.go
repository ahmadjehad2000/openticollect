package server

import "net/http"

// Stubs filled in by P3 Task 9.

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, "settings", pageData{
		Nav: "settings", Title: "Settings", Heading: "Settings",
		Description: "Resolved configuration and notifier tests.",
	})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleTestEmail(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
