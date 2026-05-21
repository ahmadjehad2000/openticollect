package store

import "testing"

func TestSettingsUpsertAndList(t *testing.T) {
	s := newTestStore(t)

	all, err := s.AllSettings()
	if err != nil {
		t.Fatalf("AllSettings: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected no settings initially, got %d", len(all))
	}

	if err := s.PutSetting("OTX_API_KEY", "abc123"); err != nil {
		t.Fatalf("PutSetting: %v", err)
	}
	if err := s.PutSetting("LOG_LEVEL", "debug"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSetting("OTX_API_KEY", "updated"); err != nil {
		t.Fatal(err)
	}

	all, err = s.AllSettings()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 settings, got %d", len(all))
	}
	if all["OTX_API_KEY"] != "updated" {
		t.Fatalf("OTX_API_KEY = %q, want the upserted value", all["OTX_API_KEY"])
	}
	if all["LOG_LEVEL"] != "debug" {
		t.Fatalf("LOG_LEVEL = %q", all["LOG_LEVEL"])
	}
}
