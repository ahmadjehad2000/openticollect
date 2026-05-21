package server

import (
	"net/http"

	"openticollect/internal/logbuf"
)

type logsData struct {
	Entries []logbuf.Entry
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	var d logsData
	if s.logs != nil {
		d.Entries = s.logs.Entries()
	}
	s.render(w, "logs", pageData{
		Nav: "logs", Title: "Logs", Heading: "Logs",
		Description: "Recent application log output, newest first.", Data: d,
	})
}

// logLevelClass maps a slog level name to a badge class.
func logLevelClass(level string) string {
	switch level {
	case "ERROR":
		return "badge-critical"
	case "WARN":
		return "badge-warn"
	case "DEBUG":
		return "badge-suppressed"
	default:
		return "badge-new"
	}
}
