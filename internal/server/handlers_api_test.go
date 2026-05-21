package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
)

func TestAPIRequiresKeyWhenConfigured(t *testing.T) {
	srv, _ := newTestServerWith(t, &config.Config{APIKey: "topsecret"})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key => status %d, want 401", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req.Header.Set("Authorization", "Bearer topsecret")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid key => status %d, want 200", rec.Code)
	}
	var body struct {
		Findings []map[string]any `json:"findings"`
		Total    int              `json:"total"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
}

func TestAPIDisabledWhenNoKey(t *testing.T) {
	srv, _ := newTestServerWith(t, &config.Config{}) // no API_KEY
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	req.Header.Set("Authorization", "Bearer anything")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("API with no key => status %d, want 503", rec.Code)
	}
}
