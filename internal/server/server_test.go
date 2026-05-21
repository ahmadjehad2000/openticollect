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
	if !strings.Contains(rec.Body.String(), `class="brand"`) {
		t.Fatal("dashboard body should contain the brand element")
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

func TestArchiveSeparatesReviewedFindings(t *testing.T) {
	srv, st := newTestServer(t)
	_, err := st.InsertFindings([]models.Finding{
		{Source: "otx", MatchedKeyword: "active-one", Severity: "warn", Excerpt: "e", Hash: "n1", Status: "new"},
		{Source: "otx", MatchedKeyword: "archived-one", Severity: "warn", Excerpt: "e", Hash: "r1", Status: "reviewed"},
	})
	if err != nil {
		t.Fatal(err)
	}

	findings := do(srv, http.MethodGet, "/findings").Body.String()
	if !strings.Contains(findings, "active-one") || strings.Contains(findings, "archived-one") {
		t.Fatal("/findings should show only new findings")
	}
	archive := do(srv, http.MethodGet, "/archive").Body.String()
	if !strings.Contains(archive, "archived-one") || strings.Contains(archive, "active-one") {
		t.Fatal("/archive should show only reviewed/suppressed findings")
	}
}

func TestFindingsBulkAction(t *testing.T) {
	srv, st := newTestServer(t)
	ins, err := st.InsertFindings([]models.Finding{
		{Source: "otx", MatchedKeyword: "a", Severity: "warn", Excerpt: "e", Hash: "b1", Status: "new"},
		{Source: "otx", MatchedKeyword: "b", Severity: "warn", Excerpt: "e", Hash: "b2", Status: "new"},
		{Source: "otx", MatchedKeyword: "c", Severity: "warn", Excerpt: "e", Hash: "b3", Status: "new"},
	})
	if err != nil {
		t.Fatal(err)
	}

	body := "action=reviewed&id=" + strconv.FormatInt(ins[0].ID, 10) +
		"&id=" + strconv.FormatInt(ins[1].ID, 10)
	rec := doForm(srv, http.MethodPost, "/findings/bulk", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /findings/bulk = %d", rec.Code)
	}
	if rec.Header().Get("HX-Refresh") != "true" {
		t.Error("bulk action should ask the client to refresh")
	}
	for i, want := range []string{"reviewed", "reviewed", "new"} {
		f, err := st.GetFinding(ins[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		if f.Status != want {
			t.Errorf("finding %d status = %q, want %q", ins[i].ID, f.Status, want)
		}
	}
}

func TestFindingsBulkRejectsBadAction(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doForm(srv, http.MethodPost, "/findings/bulk", "action=delete&id=1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad action = %d, want 400", rec.Code)
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
	t.Setenv("OTX_API_KEY", secret)
	srv, _ := newTestServer(t)

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

func TestSettingsSavePersists(t *testing.T) {
	srv, st := newTestServer(t)
	rec := doForm(srv, http.MethodPost, "/settings",
		"OTX_API_KEY=newkey123&WEBHOOK_MIN_SEVERITY=warn&EMAIL_MIN_SEVERITY=critical&LOG_LEVEL=info")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d", rec.Code)
	}
	all, err := st.AllSettings()
	if err != nil {
		t.Fatal(err)
	}
	if all["OTX_API_KEY"] != "newkey123" {
		t.Fatalf("OTX_API_KEY not persisted: %#v", all)
	}
}

func TestSettingsSaveRejectsBadSeverity(t *testing.T) {
	srv, st := newTestServer(t)
	rec := doForm(srv, http.MethodPost, "/settings", "WEBHOOK_MIN_SEVERITY=loud")
	if !strings.Contains(rec.Body.String(), "error-banner") {
		t.Fatal("invalid severity should return an error banner")
	}
	if all, _ := st.AllSettings(); len(all) != 0 {
		t.Fatal("nothing should be persisted when validation fails")
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

func TestCorrelationPageAndRuleAdd(t *testing.T) {
	srv, st := newTestServer(t)

	rec := do(srv, http.MethodGet, "/correlation")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /correlation = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Smart correlation") {
		t.Fatal("correlation page should describe the smart engine")
	}

	rec = doForm(srv, http.MethodPost, "/correlation",
		"name=watched+domains&keyword=acme.com&min_sources=2&min_count=3&window_minutes=120&severity=critical")
	if rec.Code != http.StatusOK {
		t.Fatalf("add rule = %d, want 200", rec.Code)
	}
	rules, err := st.ListCorrelationRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name != "watched domains" || rules[0].Severity != "critical" {
		t.Fatalf("rule not stored correctly: %#v", rules)
	}

	rec = doForm(srv, http.MethodPost, "/correlation",
		"name=&keyword=&min_sources=2&min_count=1&window_minutes=60&severity=warn")
	if !strings.Contains(rec.Body.String(), "error-banner") {
		t.Fatal("a rule with no name should return an error banner")
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
