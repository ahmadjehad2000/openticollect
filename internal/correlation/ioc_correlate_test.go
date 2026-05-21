package correlation

import (
	"testing"
	"time"

	"openticollect/internal/models"
)

func TestIOCCorrelateMultiSource(t *testing.T) {
	now := time.Now()
	findings := []models.Finding{
		{ID: 1, Source: "feodo", SourceURL: "http://feodo/x", MatchedKeyword: "k",
			Severity: "warn", CreatedAt: now},
		{ID: 2, Source: "pastes", SourceURL: "http://paste/y", MatchedKeyword: "k",
			Severity: "critical", CreatedAt: now},
		{ID: 3, Source: "rssfeeds", MatchedKeyword: "k", Severity: "info", CreatedAt: now},
	}
	iocs := map[int64][]models.Indicator{
		1: {{FindingID: 1, Kind: "ipv4", Value: "203.0.113.9"}},
		2: {{FindingID: 2, Kind: "ipv4", Value: "203.0.113.9"}},
		3: {{FindingID: 3, Kind: "ipv4", Value: "198.51.100.1"}},
	}
	alerts := iocCorrelate(findings, iocs, now)
	if len(alerts) != 1 {
		t.Fatalf("got %d IOC alerts, want 1 (the shared IP)", len(alerts))
	}
	if alerts[0].Keyword != "203.0.113.9" || alerts[0].Rule != "ioc-correlation" {
		t.Fatalf("unexpected alert: %+v", alerts[0])
	}
	if alerts[0].Severity != "critical" {
		t.Fatalf("alert severity should inherit the max contributing severity, got %q", alerts[0].Severity)
	}
}

func TestIOCCorrelateNilMap(t *testing.T) {
	if alerts := iocCorrelate(nil, nil, time.Now()); len(alerts) != 0 {
		t.Fatalf("nil inputs must yield no alerts, got %v", alerts)
	}
}
