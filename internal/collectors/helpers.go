package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/PuerkitoBio/goquery"
	"openticollect/internal/matcher"
	"openticollect/internal/models"
)

// scanText runs the matcher over text and builds a Finding for every keyword hit.
// This is the shared path every text-matching collector uses to produce findings.
func scanText(source, sourceURL, text, raw string, m *matcher.Matcher) []models.Finding {
	var out []models.Finding
	for _, hit := range m.Match(text) {
		out = append(out, models.Finding{
			Source:         source,
			SourceURL:      sourceURL,
			MatchedKeyword: hit.Keyword.Value,
			Severity:       hit.Keyword.Severity,
			Excerpt:        matcher.Excerpt(text, hit.Index, len(hit.Keyword.Value)),
			Raw:            raw,
			Hash:           models.HashFinding(source, sourceURL, hit.Keyword.Value),
			Status:         "new",
		})
	}
	return out
}

// fetchJSON performs an HTTP request and decodes a JSON response into out.
func fetchJSON(ctx context.Context, client *http.Client, method, url string,
	body io.Reader, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}

// fetchText performs a GET and returns the response body as a string (capped at 4 MB).
func fetchText(ctx context.Context, client *http.Client, url string,
	headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}
	return string(b), nil
}

// fetchDoc performs a GET and parses the response as an HTML document.
func fetchDoc(ctx context.Context, client *http.Client, url string) (*goquery.Document, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}
	return doc, nil
}
