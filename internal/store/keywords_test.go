package store

import "testing"

func TestKeywordCRUD(t *testing.T) {
	s := newTestStore(t)

	id, err := s.CreateKeyword("acme.com", "literal", "critical")
	if err != nil {
		t.Fatalf("CreateKeyword: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	all, err := s.ListKeywords()
	if err != nil {
		t.Fatalf("ListKeywords: %v", err)
	}
	if len(all) != 1 || all[0].Value != "acme.com" || all[0].Severity != "critical" {
		t.Fatalf("ListKeywords = %#v", all)
	}
	if !all[0].Enabled {
		t.Fatal("new keyword should be enabled")
	}

	if err := s.SetKeywordEnabled(id, false); err != nil {
		t.Fatalf("SetKeywordEnabled: %v", err)
	}
	enabled, err := s.EnabledKeywords()
	if err != nil {
		t.Fatalf("EnabledKeywords: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected 0 enabled keywords, got %d", len(enabled))
	}

	if err := s.DeleteKeyword(id); err != nil {
		t.Fatalf("DeleteKeyword: %v", err)
	}
	all, _ = s.ListKeywords()
	if len(all) != 0 {
		t.Fatalf("expected 0 keywords after delete, got %d", len(all))
	}
}

func TestCreateKeywordRejectsDuplicate(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateKeyword("dup", "literal", "warn"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateKeyword("dup", "literal", "warn"); err == nil {
		t.Fatal("expected error on duplicate (value,kind)")
	}
}

func TestCreateKeywordValidates(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateKeyword("", "literal", "warn"); err == nil {
		t.Fatal("empty value must be rejected")
	}
	if _, err := s.CreateKeyword("x", "fuzzy", "warn"); err == nil {
		t.Fatal("bad kind must be rejected")
	}
	if _, err := s.CreateKeyword("x", "literal", "loud"); err == nil {
		t.Fatal("bad severity must be rejected")
	}
}
