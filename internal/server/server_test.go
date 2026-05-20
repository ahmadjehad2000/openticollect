package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/models"
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

func TestDashboardShowsFindingAndKPIs(t *testing.T) {
	srv, st := newTestServer(t)
	if _, err := st.CreateKeyword("acme.com", "literal", "warn"); err != nil {
		t.Fatal(err)
	}
	_, err := st.InsertFindings([]models.Finding{{
		Source: "rssfeeds", SourceURL: "https://x/1", MatchedKeyword: "acme.com",
		Severity: "critical", Excerpt: "leak at acme.com", Hash: "h1", Status: "new",
	}})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(srv, http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "acme.com") {
		t.Fatal("dashboard should show the finding keyword")
	}
	if !strings.Contains(body, `<div class="kpi-value">1</div>`) {
		t.Fatal("dashboard should show a KPI value of 1")
	}
}

func TestFindingsSearchFilter(t *testing.T) {
	srv, st := newTestServer(t)
	_, err := st.InsertFindings([]models.Finding{
		{Source: "otx", MatchedKeyword: "alpha", Severity: "warn", Excerpt: "e", Hash: "a", Status: "new"},
		{Source: "otx", MatchedKeyword: "beta", Severity: "warn", Excerpt: "e", Hash: "b", Status: "new"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(srv, http.MethodGet, "/findings?q=alpha")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /findings = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, ">alpha<") || strings.Contains(body, ">beta<") {
		t.Fatal("search filter should show only the alpha finding")
	}
}

func TestFindingStatusUpdatePersists(t *testing.T) {
	srv, st := newTestServer(t)
	ins, err := st.InsertFindings([]models.Finding{
		{Source: "otx", MatchedKeyword: "k", Severity: "warn", Excerpt: "e", Hash: "h", Status: "new"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := ins[0].ID
	rec := do(srv, http.MethodPost, "/findings/"+strconv.FormatInt(id, 10)+"/status?status=reviewed")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d", rec.Code)
	}
	f, err := st.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != "reviewed" {
		t.Fatalf("status = %q, want reviewed", f.Status)
	}
}
