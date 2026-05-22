package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openticollect/internal/models"
)

func TestBuildSTIXBundle(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	inds := []models.Indicator{
		{ID: 1, FindingID: 7, Kind: "ipv4", Value: "203.0.113.7", CreatedAt: now},
		{ID: 2, FindingID: 7, Kind: "domain", Value: "evil.example.com", CreatedAt: now},
		{ID: 3, FindingID: 7, Kind: "cve", Value: "cve-2024-3094", CreatedAt: now},
	}
	b := buildSTIXBundle(inds)
	if b.Type != "bundle" || !strings.HasPrefix(b.ID, "bundle--") {
		t.Fatalf("bad bundle envelope: %+v", b)
	}
	if len(b.Objects) != 3 {
		t.Fatalf("got %d objects, want 3", len(b.Objects))
	}
	var ipPattern, cveType string
	for _, o := range b.Objects {
		if o.Pattern == "[ipv4-addr:value = '203.0.113.7']" {
			ipPattern = o.Pattern
		}
		if o.Type == "vulnerability" && o.Name == "CVE-2024-3094" {
			cveType = o.Type
		}
	}
	if ipPattern == "" {
		t.Error("missing STIX indicator pattern for the IPv4")
	}
	if cveType == "" {
		t.Error("CVE should map to a STIX vulnerability object")
	}
	if _, err := json.Marshal(b); err != nil {
		t.Fatalf("bundle not JSON-serializable: %v", err)
	}
}

func TestSTIXIDsDeterministic(t *testing.T) {
	inds := []models.Indicator{{Kind: "domain", Value: "x.com"}}
	a := buildSTIXBundle(inds).Objects[0].ID
	b := buildSTIXBundle(inds).Objects[0].ID
	if a != b {
		t.Fatalf("indicator STIX IDs must be deterministic: %q != %q", a, b)
	}
}
