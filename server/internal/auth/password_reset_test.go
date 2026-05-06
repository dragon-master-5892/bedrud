package auth

import (
	"bedrud/config"
	"bedrud/internal/email"
	"bedrud/internal/models"
	"bedrud/internal/repository"
	"bedrud/internal/testutil"
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

// resetTestEnv groups everything a password-reset test usually needs.
// Returning a single struct keeps individual tests short and lets us
// add fields later without re-touching call sites.
type resetTestEnv struct {
	svc       *AuthService
	userRepo  *repository.UserRepository
	resetRepo *repository.PasswordResetTokenRepository
	mailer    *email.LogMailer
	db        *gorm.DB
}

func setupResetEnv(t *testing.T) *resetTestEnv {
	t.Helper()
	db := testutil.SetupTestDB(t)
	userRepo := repository.NewUserRepository(db)
	passkeyRepo := repository.NewPasskeyRepository(db)
	resetRepo := repository.NewPasswordResetTokenRepository(db)
	mailer := &email.LogMailer{AppName: "Bedrud"}

	svc := NewAuthService(userRepo, passkeyRepo)
	svc.ConfigurePasswordReset(resetRepo, mailer, 15*time.Minute, "https://app.example.com")
	config.SetForTest(&config.Config{Auth: config.AuthConfig{JWTSecret: "reset-test-secret-32b-or-longer", TokenDuration: 1}})
	return &resetTestEnv{svc: svc, userRepo: userRepo, resetRepo: resetRepo, mailer: mailer, db: db}
}

func TestRequestPasswordReset_Unconfigured(t *testing.T) {
	db := testutil.SetupTestDB(t)
	svc := NewAuthService(repository.NewUserRepository(db), repository.NewPasskeyRepository(db))
	if err := svc.RequestPasswordReset("anyone@example.com"); !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("expected ErrPasswordResetUnavailable, got %v", err)
	}
}

func TestResetPassword_Unconfigured(t *testing.T) {
	db := testutil.SetupTestDB(t)
	svc := NewAuthService(repository.NewUserRepository(db), repository.NewPasskeyRepository(db))
	if err := svc.ResetPassword("any-token", "newpassword12"); !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("expected ErrPasswordResetUnavailable, got %v", err)
	}
}

func TestRequestPasswordReset_KnownLocalUser_SendsEmail(t *testing.T) {
	env := setupResetEnv(t)
	if _, err := env.svc.Register("known@example.com", "originalpass", "Known User"); err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := env.svc.RequestPasswordReset("known@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env.mailer.Sent) != 1 {
		t.Fatalf("expected 1 sent email, got %d", len(env.mailer.Sent))
	}
	msg := env.mailer.Sent[0]
	if msg.To != "known@example.com" {
		t.Fatalf("wrong recipient: %s", msg.To)
	}
	if !strings.Contains(msg.Body, "https://app.example.com/auth/reset-password?token=") {
		t.Fatalf("body missing reset link, got: %s", msg.Body)
	}
}

func TestRequestPasswordReset_UnknownEmail_NoEmailNoError(t *testing.T) {
	env := setupResetEnv(t)
	if err := env.svc.RequestPasswordReset("nobody@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env.mailer.Sent) != 0 {
		t.Fatalf("must not send email for unknown account; got %d sends", len(env.mailer.Sent))
	}
}

func TestRequestPasswordReset_OAuthAccount_NoEmailNoError(t *testing.T) {
	env := setupResetEnv(t)
	oauthUser := &models.User{
		ID: "oauth-id", Email: "oauth@example.com", Name: "OAuth", Provider: "google",
		IsActive: true, Accesses: models.StringArray{"user"},
	}
	if err := env.userRepo.CreateUser(oauthUser); err != nil {
		t.Fatalf("create oauth user: %v", err)
	}
	if err := env.svc.RequestPasswordReset("oauth@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env.mailer.Sent) != 0 {
		t.Fatalf("must not send email for OAuth account; got %d sends", len(env.mailer.Sent))
	}
}

func TestRequestPasswordReset_InactiveAccount_NoEmail(t *testing.T) {
	env := setupResetEnv(t)
	inactive := &models.User{
		ID: "inactive-id", Email: "inactive@example.com", Name: "Inactive", Provider: models.ProviderLocal,
		Password: "$2a$10$hash", IsActive: true, Accesses: models.StringArray{"user"},
	}
	if err := env.userRepo.CreateUser(inactive); err != nil {
		t.Fatalf("create inactive user: %v", err)
	}
	// GORM substitutes the column default for the bool zero-value, so the
	// row is created active and we must flip it explicitly.
	if err := env.db.Model(&models.User{}).Where("id = ?", "inactive-id").
		Update("is_active", false).Error; err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
	if err := env.svc.RequestPasswordReset("inactive@example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(env.mailer.Sent) != 0 {
		t.Fatalf("must not send email for inactive account; got %d sends", len(env.mailer.Sent))
	}
}

func TestResetPassword_HappyPath(t *testing.T) {
	env := setupResetEnv(t)
	user, err := env.svc.Register("happy@example.com", "originalpass", "Happy User")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	plain, _, err := env.resetRepo.Create(user.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := env.svc.ResetPassword(plain, "newsecurepass1"); err != nil {
		t.Fatalf("reset: %v", err)
	}

	if _, err := env.svc.Login("happy@example.com", "newsecurepass1"); err != nil {
		t.Fatalf("login with new password failed: %v", err)
	}
	if _, err := env.svc.Login("happy@example.com", "originalpass"); err == nil {
		t.Fatal("expected old password to be rejected after reset")
	}
}

func TestResetPassword_TokenIsSingleUse(t *testing.T) {
	env := setupResetEnv(t)
	user, _ := env.svc.Register("once@example.com", "originalpass", "Once User")
	plain, _, _ := env.resetRepo.Create(user.ID, 15*time.Minute)

	if err := env.svc.ResetPassword(plain, "firstnewpass1"); err != nil {
		t.Fatalf("first reset: %v", err)
	}
	if err := env.svc.ResetPassword(plain, "secondnewpass2"); err == nil {
		t.Fatal("expected second reset with same token to fail")
	}
}

func TestResetPassword_RejectsExpiredToken(t *testing.T) {
	env := setupResetEnv(t)
	user, _ := env.svc.Register("expired@example.com", "originalpass", "Expired User")

	// Seed a token with an already-elapsed lifetime by writing the model
	// directly through the same DB the repo uses.
	plain := "manually-seeded-plaintext"
	rec := &models.PasswordResetToken{
		ID:        "expired-token-id",
		UserID:    user.ID,
		Token:     repository.HashResetToken(plain),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := env.db.Create(rec).Error; err != nil {
		t.Fatalf("seed expired token: %v", err)
	}

	if err := env.svc.ResetPassword(plain, "anothernewpass1"); err == nil {
		t.Fatal("expected reset with expired token to fail")
	}
}

func TestResetPassword_RejectsUnknownToken(t *testing.T) {
	env := setupResetEnv(t)
	if err := env.svc.ResetPassword("totally-not-a-real-token", "validnewpass12"); err == nil {
		t.Fatal("expected error for unknown token")
	}
}

func TestResetPassword_EmptyTokenRejected(t *testing.T) {
	env := setupResetEnv(t)
	if err := env.svc.ResetPassword("", "validnewpass12"); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestResetPassword_RotatesRefreshToken(t *testing.T) {
	env := setupResetEnv(t)
	user, _ := env.svc.Register("rotate-rt@example.com", "originalpass", "Rotate RT")
	// Simulate an active session by stuffing a refresh-token hash on the user.
	if err := env.userRepo.UpdateRefreshToken(user.ID, "pretend-active-refresh"); err != nil {
		t.Fatalf("set initial refresh: %v", err)
	}

	plain, _, _ := env.resetRepo.Create(user.ID, 15*time.Minute)
	if err := env.svc.ResetPassword(plain, "freshpass456789"); err != nil {
		t.Fatalf("reset: %v", err)
	}

	after, _ := env.userRepo.GetUserByID(user.ID)
	if after.RefreshToken != "" {
		t.Fatal("expected refresh token to be cleared after password reset")
	}
}
