package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestNVDRunMatchesCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[
			{"cve":{"id":"CVE-2026-1234","descriptions":[
				{"lang":"en","value":"A flaw in acme-product allows remote code execution."}]}},
			{"cve":{"id":"CVE-2026-9999","descriptions":[
				{"lang":"en","value":"Unrelated issue."}]}}
		]}`))
	}))
	defer srv.Close()

	nvd := &NVD{baseURL: srv.URL}
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme-product", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := nvd.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", res.ItemsFetched)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
}

func TestNVDAlwaysEnabled(t *testing.T) {
	if !NewNVD(&config.Config{}).Enabled(nil) {
		t.Fatal("nvd is keyless and must always be enabled")
	}
}
