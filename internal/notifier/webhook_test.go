package notifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"openticollect/internal/models"
)

func TestWebhookSendSignedPayload(t *testing.T) {
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Webhook-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := newWebhookSink(srv.URL, "topsecret", "warn", srv.Client())
	wh.backoff = []time.Duration{0, 0, 0}

	f := models.Finding{ID: 7, Source: "pastebin", SourceURL: "https://p/x",
		MatchedKeyword: "acme.com", Severity: "critical", Excerpt: "leak"}
	if err := wh.Send(context.Background(), f); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var p map[string]any
	if err := json.Unmarshal(gotBody, &p); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if p["matched_keyword"] != "acme.com" || p["source"] != "pastebin" {
		t.Fatalf("payload wrong: %v", p)
	}
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write(gotBody)
	want := hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature = %q, want %q", gotSig, want)
	}
}

func TestWebhookRetriesThenFails(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wh := newWebhookSink(srv.URL, "", "warn", srv.Client())
	wh.backoff = []time.Duration{0, 0, 0}

	err := wh.Send(context.Background(), models.Finding{ID: 1, Severity: "critical"})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Fatalf("expected 4 attempts (1 + 3 retries), got %d", got)
	}
}
