package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/store"
)

type fakeNextRunner struct{}

func (fakeNextRunner) NextRun(string) (time.Time, bool) { return time.Time{}, false }

// newTestServer builds a Server backed by a temp-file store.
func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "srv.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{}
	srv, err := New(cfg, st, fakeNextRunner{}, collectors.All(cfg), discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, st
}

func do(srv *Server, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHealthz(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(srv, http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestStaticAssetServed(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(srv, http.MethodGet, "/static/style.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("static style.css = %d, want 200", rec.Code)
	}
}

func TestDashboardRoot(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(srv, http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "openticollect") {
		t.Fatal("dashboard body should contain the brand")
	}
}
