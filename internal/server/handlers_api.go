package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openticollect/internal/models"
	"openticollect/internal/store"
)

// apiGuard wraps the API mux. It returns 503 when no API key is configured
// (the API is opt-in) and 401 when the bearer token is missing or wrong.
func (s *Server) apiGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIKey == "" {
			writeJSONError(w, http.StatusServiceUnavailable,
				"API disabled: set API_KEY to enable /api/*")
			return
		}
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		if !strings.HasPrefix(got, prefix) ||
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(s.cfg.APIKey)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// apiFinding is the stable JSON shape for a finding (decoupled from the DB row).
type apiFinding struct {
	ID         int64          `json:"id"`
	Source     string         `json:"source"`
	SourceURL  string         `json:"source_url,omitempty"`
	Keyword    string         `json:"matched_keyword"`
	Severity   string         `json:"severity"`
	RiskScore  int            `json:"risk_score"`
	Status     string         `json:"status"`
	Excerpt    string         `json:"excerpt"`
	CreatedAt  time.Time      `json:"created_at"`
	Indicators []apiIndicator `json:"indicators,omitempty"`
}

type apiIndicator struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func toAPIFinding(f models.Finding) apiFinding {
	return apiFinding{
		ID: f.ID, Source: f.Source, SourceURL: f.SourceURL,
		Keyword: f.MatchedKeyword, Severity: f.Severity, RiskScore: f.RiskScore,
		Status: f.Status, Excerpt: f.Excerpt, CreatedAt: f.CreatedAt,
	}
}

// handleAPIFindings: GET /api/findings — filterable JSON list.
func (s *Server) handleAPIFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	minRisk, _ := strconv.Atoi(q.Get("min_risk"))
	statuses := []string{"new", "reviewed", "suppressed"}
	if st := q.Get("status"); st != "" {
		statuses = []string{st}
	}
	findings, total, err := s.store.ListFindings(store.FindingFilter{
		Sources:  q["source"],
		Severity: q.Get("severity"),
		Search:   strings.TrimSpace(q.Get("q")),
		Statuses: statuses,
		MinRisk:  minRisk,
		Sort:     q.Get("sort"),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, toAPIFinding(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": out, "total": total, "limit": limit, "offset": offset,
	})
}

// handleAPIFindingDetail: GET /api/findings/{id} — finding + its indicators.
func (s *Server) handleAPIFindingDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad id")
		return
	}
	f, err := s.store.GetFinding(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "finding not found")
		return
	}
	af := toAPIFinding(f)
	if inds, err := s.store.IndicatorsForFinding(id); err == nil {
		for _, in := range inds {
			af.Indicators = append(af.Indicators, apiIndicator{Kind: in.Kind, Value: in.Value})
		}
	}
	writeJSON(w, http.StatusOK, af)
}

// handleAPIIndicators: GET /api/indicators — filterable JSON list.
func (s *Server) handleAPIIndicators(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	inds, err := s.store.ListIndicators(store.IndicatorFilter{
		Kind: q.Get("kind"), Value: strings.TrimSpace(q.Get("value")),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"indicators": inds, "count": len(inds)})
}
