package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

const ahmiaResultsPage = `<html><body>
<li class="result"><h4><a href="http://abc.onion/leak">acme.com data dump</a></h4><p>desc</p></li>
<li class="result"><h4><a href="http://def.onion/x">acme.com mirror</a></h4></li>
</body></html>`

func TestDarkwebAhmiaSearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "" {
			t.Error("ahmia request missing q query param")
		}
		w.Write([]byte(ahmiaResultsPage))
	}))
	defer srv.Close()

	d := &Darkweb{ahmiaEnabled: true, ahmiaURL: srv.URL}
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := d.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
	if res.Findings[0].MatchedKeyword != "acme.com" {
		t.Errorf("MatchedKeyword = %q", res.Findings[0].MatchedKeyword)
	}
}

func TestDarkwebEnabledByDefault(t *testing.T) {
	cfg := &config.Config{EnableAhmia: true}
	if !NewDarkweb(cfg).Enabled(cfg) {
		t.Fatal("darkweb with Ahmia enabled should be enabled")
	}
}

func TestDarkwebMisconfigured(t *testing.T) {
	cfg := &config.Config{EnableAhmia: false}
	if NewDarkweb(cfg).Enabled(cfg) {
		t.Fatal("darkweb with no Ahmia and no onion URLs should be misconfigured")
	}
}
