package models

import "testing"

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"info", 0}, {"warn", 1}, {"critical", 2}, {"bogus", 0},
	}
	for _, c := range cases {
		if got := SeverityRank(c.in); got != c.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestHashFindingStable(t *testing.T) {
	a := HashFinding("otx", "https://x/1", "acme.com")
	b := HashFinding("otx", "https://x/1", "acme.com")
	c := HashFinding("otx", "https://x/2", "acme.com")
	if a != b {
		t.Fatal("HashFinding must be deterministic")
	}
	if a == c {
		t.Fatal("HashFinding must differ when source_url differs")
	}
	if len(a) != 64 {
		t.Fatalf("HashFinding length = %d, want 64 (hex sha256)", len(a))
	}
}

func TestValidSeverity(t *testing.T) {
	if !ValidSeverity("warn") || ValidSeverity("nope") {
		t.Fatal("ValidSeverity wrong")
	}
}
