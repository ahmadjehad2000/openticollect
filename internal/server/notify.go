package server

import (
	"openticollect/internal/collectors"
	"openticollect/internal/notifier"
)

// buildSinks constructs the configured notifier sinks (webhook, email) from
// config. Used by /findings resend and the /settings test buttons.
func (s *Server) buildSinks() []notifier.Sink {
	var sinks []notifier.Sink
	if wh := notifier.NewWebhookSink(s.cfg.WebhookURL, s.cfg.WebhookSecret,
		s.cfg.WebhookMinSeverity, collectors.DefaultHTTPClient()); wh != nil {
		sinks = append(sinks, wh)
	}
	if em := notifier.NewEmailSink(s.cfg.SMTPHost, s.cfg.SMTPPort, s.cfg.SMTPUser,
		s.cfg.SMTPPass, s.cfg.SMTPFrom, s.cfg.SMTPTo, s.cfg.EmailMinSeverity); em != nil {
		sinks = append(sinks, em)
	}
	return sinks
}
