package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestOTXRunMatchesPulse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") == "" {
			t.Error("OTX request missing X-OTX-API-KEY header")
		}
		w.Write([]byte(`{"results":[
			{"id":"p1","name":"Acme breach","description":"emails leaked",
			 "indicators":[{"indicator":"acme.com"}]},
			{"id":"p2","name":"unrelated","description":"nothing","indicators":[]}
		]}`))
	}))
	defer srv.Close()

	o := NewOTX(&config.Config{OTXAPIKey: "k"})
	o.baseURL = srv.URL
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := o.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", res.ItemsFetched)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if res.Findings[0].SourceURL != srv.URL+"/pulse/p1" {
		t.Errorf("SourceURL = %q", res.Findings[0].SourceURL)
	}
}

func TestOTXMissingEnv(t *testing.T) {
	o := NewOTX(&config.Config{})
	if o.Enabled(&config.Config{}) {
		t.Fatal("otx with no key should be disabled")
	}
	if got := o.MissingEnv(&config.Config{}); len(got) != 1 || got[0] != "OTX_API_KEY" {
		t.Fatalf("MissingEnv = %#v", got)
	}
}
