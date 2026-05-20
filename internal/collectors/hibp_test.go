package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openticollect/internal/models"
)

func TestHIBPRun(t *testing.T) {
	pwHash := "1234567890ABCDEF1234567890ABCDEF12345678"
	suffix := pwHash[5:]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v3/breaches":
			w.Write([]byte(`[{"Name":"Acme","Title":"Acme Breach","Domain":"acme.com","Description":"emails leaked"}]`))
		case strings.HasPrefix(r.URL.Path, "/range/"):
			w.Write([]byte(suffix + ":42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\r\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	h := &HIBP{breachesURL: srv.URL, pwnedURL: srv.URL}
	in := Input{
		Keywords: []models.Keyword{
			{ID: 1, Value: "acme.com", Kind: "literal", Severity: "warn", Enabled: true},
			{ID: 2, Value: pwHash, Kind: "literal", Severity: "critical", Enabled: true},
		},
		HTTP:   srv.Client(),
		Logger: testLogger(),
	}
	res, err := h.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// One breach-catalog match (acme.com) + one pwned-password hit.
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
}

func TestHIBPAlwaysEnabled(t *testing.T) {
	h := NewHIBP(nil)
	if !h.Enabled(nil) {
		t.Fatal("hibp is keyless and must always be enabled")
	}
}
