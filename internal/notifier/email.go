package notifier

import (
	"context"
	"fmt"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"openticollect/internal/models"
)

type emailConfig struct {
	host string
	port int
	user string
	pass string
	from string
	to   []string
}

// sendMailFunc matches smtp.SendMail; injected so tests need no SMTP server.
type sendMailFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

type emailSink struct {
	cfg      emailConfig
	min      string
	sendMail sendMailFunc
}

// NewEmailSink builds an email sink. Returns nil if host/from/to are not all set.
func NewEmailSink(host string, port int, user, pass, from string, to []string, minSeverity string) Sink {
	if host == "" || from == "" || len(to) == 0 {
		return nil
	}
	return &emailSink{
		cfg: emailConfig{host: host, port: port, user: user, pass: pass, from: from, to: to},
		min: minSeverity, sendMail: smtp.SendMail,
	}
}

func (e *emailSink) Name() string        { return "email" }
func (e *emailSink) MinSeverity() string { return e.min }

func (e *emailSink) Send(_ context.Context, f models.Finding) error {
	subject, body := buildEmailMessage(f)
	msg := "From: " + e.cfg.from + "\r\n" +
		"To: " + strings.Join(e.cfg.to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		body
	addr := e.cfg.host + ":" + strconv.Itoa(e.cfg.port)
	var auth smtp.Auth
	if e.cfg.user != "" {
		auth = smtp.PlainAuth("", e.cfg.user, e.cfg.pass, e.cfg.host)
	}
	if err := e.sendMail(addr, auth, e.cfg.from, e.cfg.to, []byte(msg)); err != nil {
		return fmt.Errorf("email: send: %w", err)
	}
	return nil
}

func buildEmailMessage(f models.Finding) (subject, body string) {
	subject = fmt.Sprintf("[openTIcollect/%s] %s: %s", f.Severity, f.Source, f.MatchedKeyword)
	body = fmt.Sprintf("Time:     %s\nSource:   %s\nURL:      %s\nKeyword:  %s\nSeverity: %s\n\n%s\n",
		time.Now().UTC().Format(time.RFC3339), f.Source, f.SourceURL,
		f.MatchedKeyword, f.Severity, f.Excerpt)
	return subject, body
}
