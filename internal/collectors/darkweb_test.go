package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openticollect/internal/config"
	"openticollect/internal/models"
)

const ahmiaHome = `<html><body>
<form id="searchForm" action="/search/" method="get">
<input id="id_q" type="search" name="q">
<input type="hidden" name="tok9" value="zz12">
</form>
</body></html>`

const ahmiaResults = `<html><body>
<li class="result"><h4><a href="/search/redirect?search_term=acme.com&redirect_url=http://abc.onion/leak">acme.com data dump</a></h4><p>fresh leak</p></li>
<li class="result"><h4><a href="/search/redirect?search_term=acme.com&redirect_url=http://def.onion/x">acme.com mirror</a></h4><p>mirror site</p></li>
</body></html>`

func TestDarkwebAhmiaSearch(t *testing.T) {
	var sawToken bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(ahmiaHome))
		case "/search/":
			if r.URL.Query().Get("tok9") == "zz12" {
				sawToken = true
			}
			w.Write([]byte(ahmiaResults))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
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
	if !sawToken {
		t.Fatal("the Ahmia search must carry the hidden form token")
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
	if res.Findings[0].SourceURL != "http://abc.onion/leak" {
		t.Fatalf("SourceURL = %q, want the real onion URL behind the redirect", res.Findings[0].SourceURL)
	}
}

func TestAhmiaOnionURL(t *testing.T) {
	cases := map[string]string{
		"/search/redirect?redirect_url=http://x.onion/p": "http://x.onion/p",
		"http://y.onion/direct":                          "http://y.onion/direct",
		"/about/":                                        "",
	}
	for in, want := range cases {
		if got := ahmiaOnionURL(in); got != want {
			t.Errorf("ahmiaOnionURL(%q) = %q, want %q", in, got, want)
		}
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
