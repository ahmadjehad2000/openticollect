package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestSecretScannerDetectsSecrets(t *testing.T) {
	page := `<html><body>
	<p>config for acme.com deployment</p>
	<script>var awsKey = "AKIAIOSFODNN7EXAMPLE";</script>
	<pre>github token: ghp_abcdefghijklmnopqrstuvwxyz0123456789</pre>
	</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(page))
	}))
	defer srv.Close()

	ss := NewSecretScanner(&config.Config{SecretScanURLs: []string{srv.URL}})
	ss.pause = 0
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := ss.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 secret findings (AWS + GitHub), got %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		// Page mentions the watched keyword, so secrets escalate to critical.
		if f.Severity != "critical" {
			t.Errorf("secret near a watched keyword should be critical, got %q", f.Severity)
		}
		if f.MatchedKeyword != "acme.com" {
			t.Errorf("expected keyword acme.com, got %q", f.MatchedKeyword)
		}
		if strings.Contains(f.Excerpt, "AKIAIOSFODNN7EXAMPLE") ||
			strings.Contains(f.Excerpt, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
			t.Errorf("the raw secret must be masked in the excerpt: %q", f.Excerpt)
		}
	}
}

func TestSecretScannerWarnWithoutKeyword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`AKIAIOSFODNN7EXAMPLE on a page with nothing watched`))
	}))
	defer srv.Close()

	ss := NewSecretScanner(&config.Config{SecretScanURLs: []string{srv.URL}})
	ss.pause = 0
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := ss.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != "warn" {
		t.Fatalf("a secret with no watched keyword should be one warn finding, got %#v", res.Findings)
	}
}

func TestSecretScannerMissingEnv(t *testing.T) {
	ss := NewSecretScanner(&config.Config{})
	if ss.Enabled(&config.Config{}) {
		t.Fatal("secret scanner with no URLs should be disabled")
	}
}

func TestMaskSecret(t *testing.T) {
	if got := maskSecret("AKIAIOSFODNN7EXAMPLE"); strings.Contains(got, "IOSFODNN7") {
		t.Fatalf("mask leaked the middle: %q", got)
	}
	if got := maskSecret("AKIAIOSFODNN7EXAMPLE"); got != "AKIA••••••MPLE" {
		t.Fatalf("maskSecret = %q", got)
	}
}
