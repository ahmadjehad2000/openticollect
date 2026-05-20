package store

import (
	"testing"
	"time"
)

func TestRecordRunAndLatest(t *testing.T) {
	s := newTestStore(t)
	start := time.Now().Add(-time.Minute)

	err := s.RecordRun("otx", start, time.Now(), true, 10, 3, "")
	if err != nil {
		t.Fatalf("RecordRun: %v", err)
	}
	err = s.RecordRun("otx", time.Now(), time.Now(), false, 0, 0, "boom")
	if err != nil {
		t.Fatal(err)
	}

	latest, err := s.LatestRun("otx")
	if err != nil {
		t.Fatalf("LatestRun: %v", err)
	}
	if latest == nil || latest.OK {
		t.Fatalf("latest run should be the failed one: %#v", latest)
	}
	if latest.Error != "boom" {
		t.Fatalf("latest run error = %q", latest.Error)
	}

	none, err := s.LatestRun("never-ran")
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatal("LatestRun for unknown source must be nil")
	}
}

func TestSourceStateToggle(t *testing.T) {
	s := newTestStore(t)

	// Unknown source defaults to enabled.
	on, err := s.SourceEnabled("otx")
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Fatal("unknown source should default to enabled")
	}

	if err := s.SetSourceEnabled("otx", false); err != nil {
		t.Fatalf("SetSourceEnabled: %v", err)
	}
	on, _ = s.SourceEnabled("otx")
	if on {
		t.Fatal("otx should now be disabled")
	}

	disabled, err := s.DisabledSources()
	if err != nil {
		t.Fatal(err)
	}
	if len(disabled) != 1 || disabled[0] != "otx" {
		t.Fatalf("DisabledSources = %#v", disabled)
	}
}
