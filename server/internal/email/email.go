// Package email provides outbound transactional email delivery.
//
// The package exposes a Mailer interface so call sites depend on behaviour
// rather than transport. Two implementations ship today:
//
//   - SMTPMailer talks to a standard SMTP relay using net/smtp (STARTTLS or
//     plain) and is the production default whenever Host is configured.
//   - LogMailer writes the message to the structured logger instead of
//     sending it. It is the safe fallback when SMTP credentials are absent
//     (local dev, CI) so the password-reset flow still completes end-to-end
//     and the link is recoverable from logs.
package email

import (
	"errors"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/rs/zerolog/log"
)

// Mailer sends transactional email. Implementations must be safe for
// concurrent use.
type Mailer interface {
	// SendPasswordReset delivers a password-reset email. The implementation
	// is responsible for building a sensible plain-text body that includes
	// the reset link; the caller supplies the link plus the recipient's
	// display name for personalization.
	SendPasswordReset(toEmail, toName, resetLink string) error
}

// Config holds connection settings for the SMTP mailer plus the From
// address to use on outbound messages. AppName is included in the email
// subject and body so users recognize the sender.
type Config struct {
	Host        string // SMTP server host. Empty disables SMTP delivery.
	Port        int    // SMTP server port (commonly 25, 465, 587).
	Username    string // Optional SMTP auth username.
	Password    string // Optional SMTP auth password.
	FromEmail   string // RFC 5322 envelope sender, e.g. "no-reply@bedrud.org".
	FromName    string // Display name shown alongside FromEmail.
	StartTLS    bool   // If true, upgrade the connection with STARTTLS.
	AppName     string // Application name used in subject lines.
	FrontendURL string // Base URL the reset link points at. Used by callers; held here for completeness.
}

// NewMailer returns an SMTPMailer when cfg.Host is set, otherwise a
// LogMailer. This lets the feature work out-of-the-box in dev without
// forcing operators to configure SMTP.
func NewMailer(cfg Config) Mailer {
	if strings.TrimSpace(cfg.Host) == "" {
		log.Warn().Msg("email: no SMTP host configured — falling back to LogMailer (reset links will be logged, not emailed)")
		return &LogMailer{AppName: cfg.AppName}
	}
	return &SMTPMailer{cfg: cfg}
}

// LogMailer writes "sent" messages to the structured log instead of
// dispatching them. Useful in development so the reset link is still
// recoverable, and in tests so we can assert delivery without a network.
type LogMailer struct {
	AppName string
	// Sent captures every delivery attempt. Tests may inspect it; production
	// callers should treat it as opaque (it is unbounded by design — keep it
	// to non-prod usage).
	Sent []LoggedMessage
}

// LoggedMessage is a single capture-record produced by LogMailer.
type LoggedMessage struct {
	To      string
	Name    string
	Subject string
	Body    string
}

// SendPasswordReset records and logs a reset email.
func (m *LogMailer) SendPasswordReset(toEmail, toName, resetLink string) error {
	subject := passwordResetSubject(m.AppName)
	body := passwordResetBody(m.AppName, toName, resetLink)
	m.Sent = append(m.Sent, LoggedMessage{To: toEmail, Name: toName, Subject: subject, Body: body})
	log.Info().
		Str("to", toEmail).
		Str("subject", subject).
		Str("reset_link", resetLink).
		Msg("email: password reset (LogMailer — not actually sent)")
	return nil
}

// SMTPMailer sends mail through a standard SMTP relay using stdlib
// net/smtp. It is intentionally minimal: one external dependency would be
// nicer for HTML email and richer auth (OAUTH2, etc.), but for a single
// plain-text reset link the stdlib is sufficient and keeps the build
// closure small.
type SMTPMailer struct {
	cfg Config
}

// SendPasswordReset assembles and dispatches the reset email.
func (m *SMTPMailer) SendPasswordReset(toEmail, toName, resetLink string) error {
	if m.cfg.FromEmail == "" {
		return errors.New("email: FromEmail is not configured")
	}
	subject := passwordResetSubject(m.cfg.AppName)
	body := passwordResetBody(m.cfg.AppName, toName, resetLink)
	return m.send(toEmail, subject, body)
}

func (m *SMTPMailer) send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	from := m.cfg.FromEmail
	fromHeader := from
	if m.cfg.FromName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", m.cfg.FromName, from)
	}

	msg := []byte("From: " + fromHeader + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"\r\n" +
		body + "\r\n")

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}

	if err := smtp.SendMail(addr, auth, from, []string{to}, msg); err != nil {
		return fmt.Errorf("email: SMTP send failed: %w", err)
	}
	return nil
}

func passwordResetSubject(appName string) string {
	if appName == "" {
		appName = "Bedrud"
	}
	return "Reset your " + appName + " password"
}

func passwordResetBody(appName, name, link string) string {
	if appName == "" {
		appName = "Bedrud"
	}
	greeting := "Hello,"
	if name != "" {
		greeting = "Hello " + name + ","
	}
	return greeting + "\n\n" +
		"We received a request to reset the password on your " + appName + " account.\n" +
		"Open the link below to choose a new password — it is valid for a short time:\n\n" +
		link + "\n\n" +
		"If you did not request this, you can safely ignore this email; your password will not change.\n\n" +
		"— " + appName
}
