package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestAbuseIPDBRunMatchesIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") == "" {
			t.Error("AbuseIPDB request missing Key header")
		}
		w.Write([]byte(`{"data":[
			{"ipAddress":"203.0.113.7","abuseConfidenceScore":92},
			{"ipAddress":"198.51.100.4","abuseConfidenceScore":80}
		]}`))
	}))
	defer srv.Close()

	a := NewAbuseIPDB(&config.Config{AbuseIPDBKey: "k"})
	a.baseURL = srv.URL
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "203.0.113.7", Kind: "literal", Severity: "critical", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := a.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", res.ItemsFetched)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != "critical" {
		t.Fatalf("findings = %#v", res.Findings)
	}
}

func TestAbuseIPDBMissingEnv(t *testing.T) {
	a := NewAbuseIPDB(&config.Config{})
	if a.Enabled(&config.Config{}) {
		t.Fatal("abuseipdb with no key should be disabled")
	}
}
