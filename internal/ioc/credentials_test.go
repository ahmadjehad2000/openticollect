package ioc

import "testing"

func TestExtractCredentialsEmailPass(t *testing.T) {
	creds := ExtractCredentials("dump:\nalice@acme.com:hunter2\nbob@acme.com:p@ss")
	if len(creds) != 2 {
		t.Fatalf("got %d creds, want 2", len(creds))
	}
	if creds[0].Username != "alice@acme.com" || creds[0].Service != "acme.com" {
		t.Errorf("cred[0] = %+v", creds[0])
	}
}

func TestExtractCredentialsStealerLog(t *testing.T) {
	// Stealer-log layout: URL:login:password
	creds := ExtractCredentials("https://mail.acme.com/login:jdoe:secretpw")
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1", len(creds))
	}
	if creds[0].Service != "mail.acme.com" || creds[0].Username != "jdoe" {
		t.Errorf("cred = %+v", creds[0])
	}
}

func TestExtractCredentialsNeverKeepsPassword(t *testing.T) {
	creds := ExtractCredentials("alice@acme.com:SuperSecret123")
	for _, c := range creds {
		// Credential carries no password field at all; assert via the masked form.
		if c.Masked == "" || credContains(c.Masked, "SuperSecret123") {
			t.Errorf("password must never be retained, got %q", c.Masked)
		}
	}
}

func credContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestExtractCredentialsIgnoresNonCreds(t *testing.T) {
	if creds := ExtractCredentials("see http://acme.com for details"); len(creds) != 0 {
		t.Errorf("got %v, want none", creds)
	}
}
