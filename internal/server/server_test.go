package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/models"
	"openticollect/internal/store"
)

type fakeNextRunner struct{}

func (fakeNextRunner) NextRun(string) (time.Time, bool) { return time.Time{}, false }

// newTestServer builds a Server backed by a temp-file store and an empty config.
func newTestServer(t *testing.T) (*Server, *store.Store) {
	return newTestServerWith(t, &config.Config{})
}

// newTestServerWith builds a Server with a caller-supplied config.
func newTestServerWith(t *testing.T, cfg *config.Config) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "srv.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
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

func doForm(srv *Server, method, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(rec, req)
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

func TestSourcesToggle(t *testing.T) {
	srv, st := newTestServerWith(t, &config.Config{RSSFeeds: []string{"https://x/feed"}})

	rec := do(srv, http.MethodGet, "/sources")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "rssfeeds") {
		t.Fatalf("GET /sources = %d, missing rssfeeds row", rec.Code)
	}
	rec = do(srv, http.MethodPost, "/sources/rssfeeds/toggle")
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle = %d, want 200", rec.Code)
	}
	on, err := st.SourceEnabled("rssfeeds")
	if err != nil {
		t.Fatal(err)
	}
	if on {
		t.Fatal("rssfeeds should be disabled after toggle")
	}
}

func TestKeywordAddAndDuplicate(t *testing.T) {
	srv, st := newTestServer(t)

	rec := doForm(srv, http.MethodPost, "/keywords", "value=acme.com&kind=literal&severity=warn")
	if rec.Code != http.StatusOK {
		t.Fatalf("add keyword = %d, want 200", rec.Code)
	}
	if kws, _ := st.ListKeywords(); len(kws) != 1 {
		t.Fatalf("expected 1 keyword, got %d", len(kws))
	}

	rec = doForm(srv, http.MethodPost, "/keywords", "value=acme.com&kind=literal&severity=warn")
	if !strings.Contains(rec.Body.String(), "error-banner") {
		t.Fatal("duplicate keyword should return an error banner")
	}
	if kws, _ := st.ListKeywords(); len(kws) != 1 {
		t.Fatalf("duplicate must not add a second keyword, got %d", len(kws))
	}
}

func TestSettingsMasksSecrets(t *testing.T) {
	secret := "supersecretkey9999"
	srv, _ := newTestServerWith(t, &config.Config{
		OTXAPIKey:          secret,
		ListenAddr:         ":8080",
		DatabasePath:       "x.db",
		LogLevel:           "info",
		WebhookMinSeverity: "warn",
		EmailMinSeverity:   "critical",
	})
	rec := do(srv, http.MethodGet, "/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /settings = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatal("raw secret leaked into the settings page")
	}
	if !strings.Contains(body, config.Mask(secret)) {
		t.Fatalf("masked secret %q missing from settings page", config.Mask(secret))
	}
}

func TestHandleTestWebhook(t *testing.T) {
	var got int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&got, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	srv, _ := newTestServerWith(t, &config.Config{
		WebhookURL: hook.URL, WebhookMinSeverity: "info", EmailMinSeverity: "info",
	})
	rec := do(srv, http.MethodPost, "/settings/test-webhook")
	if rec.Code != http.StatusOK {
		t.Fatalf("test-webhook = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "delivered") {
		t.Fatalf("expected success message, got: %s", rec.Body.String())
	}
	if atomic.LoadInt32(&got) != 1 {
		t.Fatal("the webhook endpoint did not receive the test request")
	}
}

func TestHandleTestEmailUnconfigured(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(srv, http.MethodPost, "/settings/test-email")
	if rec.Code != http.StatusOK {
		t.Fatalf("test-email = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not fully configured") {
		t.Fatalf("expected a graceful 'not configured' message, got: %s", rec.Body.String())
	}
}
