package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestCISAKEVRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[
			{"cveID":"CVE-2026-1000","vendorProject":"Acme","product":"acme-router",
			 "vulnerabilityName":"Acme Router RCE","shortDescription":"remote code execution"},
			{"cveID":"CVE-2026-2000","vendorProject":"Other","product":"thing",
			 "vulnerabilityName":"unrelated","shortDescription":"nothing"}
		]}`))
	}))
	defer srv.Close()

	c := &CISAKEV{url: srv.URL}
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme-router", Kind: "literal", Severity: "critical", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := c.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", res.ItemsFetched)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if res.Findings[0].SourceURL != "https://nvd.nist.gov/vuln/detail/CVE-2026-1000" {
		t.Errorf("SourceURL = %q", res.Findings[0].SourceURL)
	}
}

func TestCISAKEVAlwaysEnabled(t *testing.T) {
	if !NewCISAKEV(&config.Config{}).Enabled(nil) {
		t.Fatal("cisakev is keyless and must always be enabled")
	}
}

func TestFeodoRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"ip_address":"203.0.113.10","port":443,"malware":"Emotet","as_name":"EvilAS","country":"RU"},
			{"ip_address":"198.51.100.20","port":8080,"malware":"Dridex","as_name":"OtherAS","country":"US"}
		]`))
	}))
	defer srv.Close()

	f := &Feodo{url: srv.URL}
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "203.0.113.10", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := f.Run(context.Background(), in)
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

func TestFeodoAlwaysEnabled(t *testing.T) {
	if !NewFeodo(&config.Config{}).Enabled(nil) {
		t.Fatal("feodo is keyless and must always be enabled")
	}
}
