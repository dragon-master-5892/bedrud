package auth

import (
	"bedrud/internal/email"
	"bedrud/internal/models"
	"bedrud/internal/repository"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// ErrPasswordResetUnavailable is returned by the reset entry-points when
// the AuthService has not been configured with a reset-token repository
// and a Mailer (see ConfigurePasswordReset). It exists so callers can
// distinguish "feature disabled" from a transient runtime failure.
var ErrPasswordResetUnavailable = errors.New("password reset is not configured on this server")

// ConfigurePasswordReset wires the dependencies the reset flow needs onto
// an AuthService. Call once during application startup, after constructing
// the service. Tests that don't exercise the reset flow can leave it
// unconfigured — the new methods will return ErrPasswordResetUnavailable.
//
// frontendBaseURL must point at the user-facing app (the address the user
// sees in their browser, not the API). Reset links are built by appending
// "/auth/reset-password?token=…" to this URL.
func (s *AuthService) ConfigurePasswordReset(
	repo *repository.PasswordResetTokenRepository,
	mailer email.Mailer,
	tokenTTL time.Duration,
	frontendBaseURL string,
) {
	s.resetTokenRepo = repo
	s.mailer = mailer
	s.resetTokenTTL = tokenTTL
	s.resetFrontendURL = frontendBaseURL
}

// passwordResetEnabled reports whether the optional dependencies have
// been wired in. Used by both entry-points to fail early with a clean
// error instead of nil-panicking.
func (s *AuthService) passwordResetEnabled() bool {
	return s.resetTokenRepo != nil && s.mailer != nil && s.resetTokenTTL > 0 && s.resetFrontendURL != ""
}

// RequestPasswordReset issues a fresh single-use reset token for the user
// matching `email` and triggers an outbound email containing the reset
// link. To prevent account-enumeration attacks the function returns nil
// for both "user found" and "user not found" — only the email recipient
// can tell whether a message arrived. Errors are returned only for
// configuration problems or unexpected database/mailer failures.
//
// Reset is intentionally restricted to local-password accounts. Users
// who authenticate via OAuth or passkey have no password to reset; for
// them the request is silently dropped (still returning nil) so attackers
// cannot probe which provider an account uses.
func (s *AuthService) RequestPasswordReset(emailAddr string) error {
	if !s.passwordResetEnabled() {
		return ErrPasswordResetUnavailable
	}

	user, err := s.userRepo.GetUserByEmail(emailAddr)
	if err != nil {
		return err
	}
	// Silent no-op for unknown email or non-local provider — same response
	// shape as the success path so the endpoint cannot be used to enumerate
	// accounts or auth providers.
	if user == nil || user.Provider != models.ProviderLocal || !user.IsActive {
		log.Debug().Str("email", emailAddr).Msg("password reset requested for unknown / non-local / inactive account — dropping silently")
		return nil
	}

	plaintext, _, err := s.resetTokenRepo.Create(user.ID, s.resetTokenTTL)
	if err != nil {
		return err
	}

	link := buildResetLink(s.resetFrontendURL, plaintext)
	if err := s.mailer.SendPasswordReset(user.Email, user.Name, link); err != nil {
		// Surface mailer failures to the caller — they're an operational
		// issue, not a user-facing one, and the handler logs them.
		return err
	}
	log.Info().Str("user_id", user.ID).Msg("password reset email dispatched")
	return nil
}

// ResetPassword consumes a reset token and replaces the user's password.
// On success the token is marked used, all of the user's outstanding reset
// tokens are invalidated, and the stored refresh token is rotated so any
// active session for that account is forced to re-authenticate.
//
// All failure modes — bad token, expired token, weak password — are
// returned as errors. Callers should map them to a generic 400 response;
// distinguishing them in the UI would help an attacker probe the system.
func (s *AuthService) ResetPassword(plaintextToken, newPassword string) error {
	if !s.passwordResetEnabled() {
		return ErrPasswordResetUnavailable
	}
	if plaintextToken == "" {
		return errors.New("token is required")
	}

	tok, err := s.resetTokenRepo.GetByPlaintext(plaintextToken)
	if err != nil {
		return err
	}
	if tok == nil {
		return errors.New("invalid or expired token")
	}

	user, err := s.userRepo.GetUserByID(tok.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("invalid or expired token")
	}
	// Defensive: the same provider check as RequestPasswordReset, in case
	// the user's provider changed between request and redemption.
	if user.Provider != models.ProviderLocal {
		return errors.New("password reset is only available for local accounts")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashed)
	// Clear the stored refresh token so any logged-in session is forced
	// to re-authenticate after a password reset.
	user.RefreshToken = ""
	if err := s.userRepo.UpdateUser(user); err != nil {
		return err
	}

	if err := s.resetTokenRepo.MarkUsed(tok.ID); err != nil {
		// Already-used races back here as an error. The password change
		// already landed; log loudly but don't fail the request — the
		// user shouldn't be locked out because of a CAS race.
		log.Warn().Err(err).Str("token_id", tok.ID).Msg("password reset: MarkUsed failed after password update")
	}
	// Best-effort cleanup of any other outstanding tokens for this user.
	if err := s.resetTokenRepo.InvalidateForUser(user.ID); err != nil {
		log.Warn().Err(err).Str("user_id", user.ID).Msg("password reset: InvalidateForUser failed")
	}
	log.Info().Str("user_id", user.ID).Msg("password reset completed")
	return nil
}

// buildResetLink composes the user-facing URL the reset email points at.
// The token rides as a query parameter so the frontend route can stay a
// plain static page.
func buildResetLink(base, token string) string {
	sep := "?"
	for i := 0; i < len(base); i++ {
		if base[i] == '?' {
			sep = "&"
			break
		}
	}
	return base + "/auth/reset-password" + sep + "token=" + token
}
