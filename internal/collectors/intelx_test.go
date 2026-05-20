package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestIntelXRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-key") == "" {
			t.Error("intelx request missing x-key header")
		}
		switch r.URL.Path {
		case "/intelligent/search":
			w.Write([]byte(`{"id":"abc"}`))
		case "/intelligent/search/result":
			w.Write([]byte(`{"records":[{"systemid":"s1","name":"acme dump","bucket":"leaks"}]}`))
		}
	}))
	defer srv.Close()

	i := NewIntelX(&config.Config{IntelXKey: "k"})
	i.baseURL = srv.URL
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := i.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if res.Findings[0].MatchedKeyword != "acme.com" {
		t.Errorf("MatchedKeyword = %q", res.Findings[0].MatchedKeyword)
	}
}

func TestIntelXMissingEnv(t *testing.T) {
	i := NewIntelX(&config.Config{})
	if i.Enabled(&config.Config{}) {
		t.Fatal("intelx with no key should be disabled")
	}
}
