package server

import "net/http"

// handleDashboard is a stub filled in by P3 Task 5.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.render(w, "dashboard", pageData{
		Nav: "", Title: "Dashboard", Heading: "Dashboard",
		Description: "Overview of collection activity.",
	})
}
