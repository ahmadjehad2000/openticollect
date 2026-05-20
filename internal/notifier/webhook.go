package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"openticollect/internal/models"
)

type webhookSink struct {
	url     string
	secret  string
	min     string
	http    *http.Client
	host    string
	backoff []time.Duration // wait before each retry
}

// NewWebhookSink builds a webhook sink. Returns nil if url is empty.
func NewWebhookSink(url, secret, minSeverity string, client *http.Client) Sink {
	if url == "" {
		return nil
	}
	return newWebhookSink(url, secret, minSeverity, client)
}

func newWebhookSink(url, secret, minSeverity string, client *http.Client) *webhookSink {
	host, _ := os.Hostname()
	if host == "" {
		host = "openticollect"
	}
	return &webhookSink{
		url: url, secret: secret, min: minSeverity, http: client, host: host,
		backoff: []time.Duration{1 * time.Second, 4 * time.Second, 16 * time.Second},
	}
}

func (w *webhookSink) Name() string        { return "webhook" }
func (w *webhookSink) MinSeverity() string { return w.min }

type webhookPayload struct {
	ID             int64  `json:"id"`
	Timestamp      string `json:"timestamp"`
	Source         string `json:"source"`
	SourceURL      string `json:"source_url"`
	MatchedKeyword string `json:"matched_keyword"`
	Severity       string `json:"severity"`
	Excerpt        string `json:"excerpt"`
	Host           string `json:"host"`
}

func (w *webhookSink) Send(ctx context.Context, f models.Finding) error {
	body, err := json.Marshal(webhookPayload{
		ID:             f.ID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Source:         f.Source,
		SourceURL:      f.SourceURL,
		MatchedKeyword: f.MatchedKeyword,
		Severity:       f.Severity,
		Excerpt:        f.Excerpt,
		Host:           w.host,
	})
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= len(w.backoff); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(w.backoff[attempt-1]):
			}
		}
		if lastErr = w.post(ctx, body); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("webhook: all attempts failed: %w", lastErr)
}

func (w *webhookSink) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(body)
		req.Header.Set("X-Webhook-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: status %d", resp.StatusCode)
	}
	return nil
}
