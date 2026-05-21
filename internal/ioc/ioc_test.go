package ioc

import (
	"reflect"
	"sort"
	"testing"
)

func sortedValues(inds []Indicator) []string {
	v := make([]string, len(inds))
	for i, in := range inds {
		v[i] = string(in.Kind) + ":" + in.Value
	}
	sort.Strings(v)
	return v
}

func TestExtractMixed(t *testing.T) {
	text := `Dump from 203.0.113.7 and hxxps://evil[.]example[.]com/leak
	contact admin@acme.com hash d41d8cd98f00b204e9800998ecf8427e
	see CVE-2024-3094 wallet bc1q9zpgru8m5v3d3w0v2v0n6q8g8m5v3d3w0v2v0`
	got := sortedValues(Extract(text))
	want := []string{
		"cve:cve-2024-3094",
		"domain:evil.example.com",
		"email:admin@acme.com",
		"ipv4:203.0.113.7",
		"md5:d41d8cd98f00b204e9800998ecf8427e",
		"url:https://evil.example.com/leak",
	}
	// btc is variable-length; assert it is present separately.
	hasBTC := false
	for _, in := range Extract(text) {
		if in.Kind == KindBTC {
			hasBTC = true
		}
	}
	if !hasBTC {
		t.Errorf("expected a btc indicator")
	}
	gotNoBTC := got[:0]
	for _, v := range got {
		if v[:3] != "btc" {
			gotNoBTC = append(gotNoBTC, v)
		}
	}
	if !reflect.DeepEqual(gotNoBTC, want) {
		t.Errorf("Extract() = %v, want %v", gotNoBTC, want)
	}
}

func TestExtractDedupAndNormalize(t *testing.T) {
	got := Extract("ACME.COM acme.com Acme.Com")
	if len(got) != 1 || got[0].Value != "acme.com" {
		t.Fatalf("Extract should dedup case-insensitively, got %v", got)
	}
}

func TestExtractIgnoresFileNames(t *testing.T) {
	for _, s := range []string{"index.php", "report.txt", "photo.jpg", "data.json"} {
		if inds := Extract(s); len(inds) != 0 {
			t.Errorf("Extract(%q) = %v, want none (file name, not domain)", s, inds)
		}
	}
}

func TestExtractHashKinds(t *testing.T) {
	cases := map[string]Kind{
		"d41d8cd98f00b204e9800998ecf8427e":                                 KindMD5,
		"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         KindSHA1,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": KindSHA256,
	}
	for h, want := range cases {
		inds := Extract("hash " + h)
		if len(inds) != 1 || inds[0].Kind != want {
			t.Errorf("Extract(%q) kind = %v, want %v", h, inds, want)
		}
	}
}
