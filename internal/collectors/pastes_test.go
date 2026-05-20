package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/models"
)

func TestPastesRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/archive":
			w.Write([]byte(`<table class="maintable">
				<tr><td><a href="/abcd1234">x</a></td></tr>
				<tr><td><a href="/efgh5678">y</a></td></tr></table>`))
		case "/raw/abcd1234":
			w.Write([]byte("dump of emails from acme.com here"))
		case "/raw/efgh5678":
			w.Write([]byte("nothing relevant"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := &Pastes{
		archiveURL: srv.URL + "/archive",
		rawBase:    srv.URL + "/raw/",
		pause:      0,
		maxPastes:  20,
	}
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
	if res.ItemsFetched != 2 {
		t.Errorf("ItemsFetched = %d, want 2", res.ItemsFetched)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
}

func TestPastesAlwaysEnabled(t *testing.T) {
	if !NewPastes(nil).Enabled(nil) {
		t.Fatal("pastes is keyless and must always be enabled")
	}
}
