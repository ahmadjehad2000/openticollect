package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestAbuseCHRunAcrossEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-Key") == "" {
			t.Error("abuse.ch request missing Auth-Key header")
		}
		switch r.URL.Path {
		case "/urlhaus":
			w.Write([]byte(`{"urls":[{"url":"http://evil.acme.com/x","threat":"malware_download"}]}`))
		case "/threatfox":
			w.Write([]byte(`{"data":[{"ioc":"bad.example","malware":"x","threat_type":"botnet_cc"}]}`))
		case "/bazaar":
			w.Write([]byte(`{"data":[{"sha256_hash":"abc123","file_name":"acme.exe","signature":"Trojan"}]}`))
		}
	}))
	defer srv.Close()

	a := NewAbuseCH(&config.Config{AbuseCHKey: "k"})
	a.urlhausURL = srv.URL + "/urlhaus"
	a.threatfoxURL = srv.URL + "/threatfox"
	a.bazaarURL = srv.URL + "/bazaar"

	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := a.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// "acme" matches the URLhaus URL and the MalwareBazaar file name.
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
}

func TestAbuseCHMissingEnv(t *testing.T) {
	a := NewAbuseCH(&config.Config{})
	if a.Enabled(&config.Config{}) {
		t.Fatal("abusech with no key should be disabled")
	}
}
