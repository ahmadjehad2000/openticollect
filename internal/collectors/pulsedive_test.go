package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

func TestPulsediveRunMatchesIndicator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			t.Error("pulsedive request missing key query param")
		}
		w.Write([]byte(`{"results":[
			{"indicator":"acme.com","type":"domain","risk":"high"},
			{"indicator":"safe.example","type":"domain","risk":"low"}
		]}`))
	}))
	defer srv.Close()

	p := NewPulsedive(&config.Config{PulsediveKey: "k"})
	p.baseURL = srv.URL
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := p.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemsFetched != 2 || len(res.Findings) != 1 {
		t.Fatalf("items=%d findings=%d", res.ItemsFetched, len(res.Findings))
	}
}

func TestPulsediveMissingEnv(t *testing.T) {
	p := NewPulsedive(&config.Config{})
	if p.Enabled(&config.Config{}) {
		t.Fatal("pulsedive with no key should be disabled")
	}
}
