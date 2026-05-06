package handlers

import (
	"bedrud/config"
	"bedrud/internal/auth"
	"bedrud/internal/email"
	"bedrud/internal/repository"
	"bedrud/internal/testutil"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// resetTestApp wires a Fiber app exposing the two reset endpoints, with
// the AuthService configured against an in-memory mailer so tests can
// assert on outbound email.
type resetTestApp struct {
	app       *fiber.App
	svc       *auth.AuthService
	userRepo  *repository.UserRepository
	resetRepo *repository.PasswordResetTokenRepository
	mailer    *email.LogMailer
}

func setupResetHandlerApp(t *testing.T, configured bool) *resetTestApp {
	t.Helper()
	db := testutil.SetupTestDB(t)
	userRepo := repository.NewUserRepository(db)
	passkeyRepo := repository.NewPasskeyRepository(db)
	resetRepo := repository.NewPasswordResetTokenRepository(db)
	mailer := &email.LogMailer{AppName: "Bedrud"}

	cfg := &config.Config{
		Auth:   config.AuthConfig{JWTSecret: "reset-handler-test-secret-32b!", TokenDuration: 1},
		Server: config.ServerConfig{Domain: "localhost"},
	}
	config.SetForTest(cfg)

	authService := auth.NewAuthService(userRepo, passkeyRepo)
	if configured {
		authService.ConfigurePasswordReset(resetRepo, mailer, 15*time.Minute, "https://app.example.com")
	}

	authHandler := NewAuthHandler(authService, cfg, nil, nil)
	app := fiber.New()
	app.Post("/api/auth/forgot-password", authHandler.ForgotPassword)
	app.Post("/api/auth/reset-password", authHandler.ResetPassword)

	return &resetTestApp{app: app, svc: authService, userRepo: userRepo, resetRepo: resetRepo, mailer: mailer}
}

func postJSON(t *testing.T, app *fiber.App, path string, body any) (*http.Response, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// --- ForgotPassword -------------------------------------------------------

func TestForgotPassword_KnownUser_ReturnsGenericMessageAndSends(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	if _, err := env.svc.Register("known@example.com", "originalpass", "Known"); err != nil {
		t.Fatalf("register: %v", err)
	}

	resp, body := postJSON(t, env.app, "/api/auth/forgot-password", fiber.Map{"email": "known@example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", resp.StatusCode, body)
	}
	var out ForgotPasswordResponse
	_ = json.Unmarshal(body, &out)
	if out.Message != genericForgotPasswordMessage {
		t.Fatalf("unexpected message: %q", out.Message)
	}
	if len(env.mailer.Sent) != 1 {
		t.Fatalf("expected 1 sent email, got %d", len(env.mailer.Sent))
	}
}

func TestForgotPassword_UnknownUser_ReturnsSameGenericMessage(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	resp, body := postJSON(t, env.app, "/api/auth/forgot-password", fiber.Map{"email": "ghost@example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", resp.StatusCode, body)
	}
	var out ForgotPasswordResponse
	_ = json.Unmarshal(body, &out)
	if out.Message != genericForgotPasswordMessage {
		t.Fatalf("unexpected message: %q", out.Message)
	}
	if len(env.mailer.Sent) != 0 {
		t.Fatal("must not send email for unknown account")
	}
}

func TestForgotPassword_InvalidEmail_Returns400(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	resp, _ := postJSON(t, env.app, "/api/auth/forgot-password", fiber.Map{"email": "not-an-email"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestForgotPassword_InvalidBody_Returns400(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte("{invalid")))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := env.app.Test(req, -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestForgotPassword_NotConfigured_Returns503(t *testing.T) {
	env := setupResetHandlerApp(t, false)
	resp, _ := postJSON(t, env.app, "/api/auth/forgot-password", fiber.Map{"email": "anyone@example.com"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

// --- ResetPassword --------------------------------------------------------

func TestResetPassword_HappyPath_ReturnsSuccessAndUpdatesPassword(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	user, _ := env.svc.Register("happy@example.com", "originalpass", "Happy")

	plain, _, err := env.resetRepo.Create(user.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}

	resp, body := postJSON(t, env.app, "/api/auth/reset-password", fiber.Map{
		"token":       plain,
		"newPassword": "newsecurepass1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Password updated") {
		t.Fatalf("unexpected body: %s", body)
	}

	if _, err := env.svc.Login("happy@example.com", "newsecurepass1"); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
}

func TestResetPassword_InvalidToken_Returns400(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	resp, _ := postJSON(t, env.app, "/api/auth/reset-password", fiber.Map{
		"token":       "totally-not-a-real-token",
		"newPassword": "validnewpass12",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestResetPassword_MissingToken_Returns400(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	resp, _ := postJSON(t, env.app, "/api/auth/reset-password", fiber.Map{
		"token":       "",
		"newPassword": "validnewpass12",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestResetPassword_PasswordTooShort_Returns400(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	user, _ := env.svc.Register("short@example.com", "originalpass", "Short")
	plain, _, _ := env.resetRepo.Create(user.ID, 15*time.Minute)

	resp, _ := postJSON(t, env.app, "/api/auth/reset-password", fiber.Map{
		"token":       plain,
		"newPassword": "shortie",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestResetPassword_PasswordTooLong_Returns400(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	user, _ := env.svc.Register("long@example.com", "originalpass", "Long")
	plain, _, _ := env.resetRepo.Create(user.ID, 15*time.Minute)

	resp, _ := postJSON(t, env.app, "/api/auth/reset-password", fiber.Map{
		"token":       plain,
		"newPassword": strings.Repeat("a", 200),
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestResetPassword_InvalidBody_Returns400(t *testing.T) {
	env := setupResetHandlerApp(t, true)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader([]byte("{invalid")))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := env.app.Test(req, -1)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestResetPassword_NotConfigured_Returns503(t *testing.T) {
	env := setupResetHandlerApp(t, false)
	resp, _ := postJSON(t, env.app, "/api/auth/reset-password", fiber.Map{
		"token":       "any",
		"newPassword": "validnewpass12",
	})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}
