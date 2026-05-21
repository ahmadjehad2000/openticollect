package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

const tgPreviewPage = `<html><body>
<div class="tgme_widget_message">
  <a class="tgme_widget_message_date" href="https://t.me/leakchan/5"></a>
  <div class="tgme_widget_message_text">fresh database from acme.com for sale</div>
</div>
<div class="tgme_widget_message">
  <div class="tgme_widget_message_text">unrelated channel chatter</div>
</div>
</body></html>`

func TestTelegramRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(tgPreviewPage))
	}))
	defer srv.Close()

	tg := NewTelegram(&config.Config{TelegramChannels: []string{"@leakchan"}})
	tg.baseURL = srv.URL
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "critical", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := tg.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Recent scan + per-keyword search both find the same message; the store
	// would dedup, but the collector reports one finding per keyword hit here.
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one telegram finding")
	}
	for _, f := range res.Findings {
		if f.MatchedKeyword != "acme.com" {
			t.Fatalf("unexpected keyword %q", f.MatchedKeyword)
		}
	}
}

func TestTelegramSearchesPerKeyword(t *testing.T) {
	var queried int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "" {
			atomic.AddInt32(&queried, 1)
		}
		w.Write([]byte(tgPreviewPage))
	}))
	defer srv.Close()

	tg := NewTelegram(&config.Config{TelegramChannels: []string{"@leakchan"}})
	tg.baseURL = srv.URL
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	if _, err := tg.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt32(&queried) == 0 {
		t.Fatal("telegram should issue a per-keyword ?q= search, not just scrape recent messages")
	}
}

func TestTelegramMissingEnv(t *testing.T) {
	tg := NewTelegram(&config.Config{})
	if tg.Enabled(&config.Config{}) {
		t.Fatal("telegram with no channels should be disabled")
	}
}
