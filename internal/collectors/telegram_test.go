package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	if res.ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", res.ItemsFetched)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if res.Findings[0].SourceURL != "https://t.me/leakchan/5" {
		t.Errorf("SourceURL = %q", res.Findings[0].SourceURL)
	}
}

func TestTelegramMissingEnv(t *testing.T) {
	tg := NewTelegram(&config.Config{})
	if tg.Enabled(&config.Config{}) {
		t.Fatal("telegram with no channels should be disabled")
	}
}
