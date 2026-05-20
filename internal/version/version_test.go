package version

import "testing"

func TestVersionHasDefault(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must have a non-empty default")
	}
}

func TestStringIncludesProduct(t *testing.T) {
	if got := String(); got != "openTIcollect/"+Version {
		t.Fatalf("String() = %q, want %q", got, "openTIcollect/"+Version)
	}
}
