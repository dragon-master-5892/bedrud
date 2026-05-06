package email

import (
	"strings"
	"testing"
)

func TestNewMailer_DefaultsToLogMailerWhenHostUnset(t *testing.T) {
	m := NewMailer(Config{AppName: "Bedrud"})
	if _, ok := m.(*LogMailer); !ok {
		t.Fatalf("expected LogMailer when Host is empty, got %T", m)
	}
}

func TestNewMailer_ReturnsSMTPMailerWhenHostSet(t *testing.T) {
	m := NewMailer(Config{Host: "smtp.example.com", Port: 587, FromEmail: "no-reply@example.com"})
	if _, ok := m.(*SMTPMailer); !ok {
		t.Fatalf("expected SMTPMailer when Host is set, got %T", m)
	}
}

func TestLogMailer_SendPasswordReset_CapturesMessage(t *testing.T) {
	m := &LogMailer{AppName: "TestApp"}
	if err := m.SendPasswordReset("user@example.com", "Alice", "https://example.com/reset?token=abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Sent) != 1 {
		t.Fatalf("expected 1 captured message, got %d", len(m.Sent))
	}
	got := m.Sent[0]
	if got.To != "user@example.com" {
		t.Fatalf("wrong To: %s", got.To)
	}
	if !strings.Contains(got.Subject, "TestApp") {
		t.Fatalf("subject should mention app name, got %q", got.Subject)
	}
	if !strings.Contains(got.Body, "Alice") {
		t.Fatalf("body should greet by name, got %q", got.Body)
	}
	if !strings.Contains(got.Body, "https://example.com/reset?token=abc") {
		t.Fatalf("body must include the reset link")
	}
}

func TestLogMailer_DefaultAppNameUsedWhenEmpty(t *testing.T) {
	m := &LogMailer{}
	_ = m.SendPasswordReset("user@example.com", "", "https://example.com/x")
	if !strings.Contains(m.Sent[0].Subject, "Bedrud") {
		t.Fatalf("expected default app name 'Bedrud' in subject, got %q", m.Sent[0].Subject)
	}
	if !strings.Contains(m.Sent[0].Body, "Hello,") {
		t.Fatalf("expected anonymous greeting when name is empty, got %q", m.Sent[0].Body)
	}
}

func TestSMTPMailer_SendPasswordReset_RequiresFromEmail(t *testing.T) {
	m := &SMTPMailer{cfg: Config{Host: "smtp.example.com", Port: 587}}
	err := m.SendPasswordReset("u@example.com", "U", "https://example.com/x")
	if err == nil {
		t.Fatal("expected error when FromEmail is empty")
	}
	if !strings.Contains(err.Error(), "FromEmail") {
		t.Fatalf("expected error to mention FromEmail, got %v", err)
	}
}
