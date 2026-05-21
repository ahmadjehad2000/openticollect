package scheduler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"openticollect/internal/collectors"
	"openticollect/internal/config"
	"openticollect/internal/models"
	"openticollect/internal/notifier"
	"openticollect/internal/store"
)

// TestSmokeCollectorToStoreToWebhook wires a fake collector through the real
// scheduler, store, notifier, and a real webhook sink hitting an httptest server.
func TestSmokeCollectorToStoreToWebhook(t *testing.T) {
	var hookHits int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		atomic.AddInt32(&hookHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "smoke.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	sink := notifier.NewWebhookSink(hook.URL, "secret", "warn", hook.Client())
	n := notifier.New(nil, sink)

	finding := models.Finding{
		Source: "fake", SourceURL: "https://x/1", MatchedKeyword: "acme.com",
		Severity: "critical", Excerpt: "leak", Hash: models.HashFinding("fake", "https://x/1", "acme.com"),
	}
	fc := &fakeCollector{name: "fake", findings: []models.Finding{finding}}

	s := New(&config.Config{}, st, n, []collectors.Collector{fc}, nil,
		collectors.DefaultHTTPClient(), nil, nil)

	if err := s.runCollector(context.Background(), fc); err != nil {
		t.Fatalf("runCollector: %v", err)
	}

	_, total, _ := st.ListFindings(store.FindingFilter{Limit: 50})
	if total != 1 {
		t.Fatalf("expected 1 stored finding, got %d", total)
	}
	if got := atomic.LoadInt32(&hookHits); got != 1 {
		t.Fatalf("expected webhook to fire once, got %d", got)
	}
	stored, _, _ := st.ListFindings(store.FindingFilter{Limit: 50})
	if stored[0].NotifiedAt == nil {
		t.Fatal("finding should be marked notified after dispatch")
	}
}
