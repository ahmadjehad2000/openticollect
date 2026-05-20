package notifier

import (
	"context"
	"net/smtp"
	"strings"
	"testing"

	"openticollect/internal/models"
)

func TestBuildEmailMessage(t *testing.T) {
	f := models.Finding{
		Source: "pastebin", SourceURL: "https://p/x",
		MatchedKeyword: "acme.com", Severity: "critical", Excerpt: "the leak text",
	}
	subject, body := buildEmailMessage(f)
	if subject != "[openTIcollect/critical] pastebin: acme.com" {
		t.Fatalf("subject = %q", subject)
	}
	for _, want := range []string{"https://p/x", "the leak text", "pastebin"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
}

func TestEmailSinkSend(t *testing.T) {
	var gotTo []string
	var gotMsg string
	es := &emailSink{
		cfg: emailConfig{host: "smtp.test", port: 587, from: "a@b.c", to: []string{"x@y.z"}},
		min: "critical",
		sendMail: func(addr string, _ smtp.Auth, _ string, to []string, msg []byte) error {
			gotTo = to
			gotMsg = string(msg)
			return nil
		},
	}
	err := es.Send(context.Background(), models.Finding{
		Source: "otx", MatchedKeyword: "k", Severity: "critical", Excerpt: "e"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(gotTo) != 1 || gotTo[0] != "x@y.z" {
		t.Fatalf("recipients = %#v", gotTo)
	}
	if !strings.Contains(gotMsg, "Subject: [openTIcollect/critical] otx: k") {
		t.Fatalf("message missing subject header:\n%s", gotMsg)
	}
}
