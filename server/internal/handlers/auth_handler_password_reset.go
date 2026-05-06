package handlers

import (
	"bedrud/internal/auth"
	"errors"
	"fmt"
	"net/mail"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

// ForgotPasswordRequest is the request body for ForgotPassword.
type ForgotPasswordRequest struct {
	Email string `json:"email" example:"user@example.com"`
}

// ForgotPasswordResponse is the response body for ForgotPassword. It is
// always the same regardless of whether the email matched a real account
// — see ForgotPassword for the rationale.
type ForgotPasswordResponse struct {
	Message string `json:"message" example:"If an account exists for that email, a reset link has been sent."`
}

// ResetPasswordRequest is the request body for ResetPassword.
type ResetPasswordRequest struct {
	Token       string `json:"token" example:"raw-token-from-email"`
	NewPassword string `json:"newPassword" example:"new-strong-password"`
}

// ResetPasswordResponse is the response body for a successful reset.
type ResetPasswordResponse struct {
	Message string `json:"message" example:"Password updated successfully"`
}

// genericForgotPasswordMessage is the message returned from
// ForgotPassword regardless of whether the email matched an account. The
// constant is used in the response and surfaced through the Swagger
// example so clients see the same string everywhere.
const genericForgotPasswordMessage = "If an account exists for that email, a reset link has been sent."

// ForgotPassword starts the password-reset flow.
//
// @Summary      Request a password reset email
// @Description  Sends a reset link to the supplied email if it matches a local account. The response is identical for known and unknown emails so the endpoint cannot be used to enumerate accounts.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      ForgotPasswordRequest   true  "Email to send the reset link to"
// @Success      200      {object}  ForgotPasswordResponse
// @Failure      400      {object}  auth.ErrorResponse
// @Failure      503      {object}  auth.ErrorResponse  "Reset is not configured on this server"
// @Router       /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *fiber.Ctx) error {
	var input ForgotPasswordRequest
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}
	if _, err := mail.ParseAddress(input.Email); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid email format"})
	}

	if err := h.authService.RequestPasswordReset(input.Email); err != nil {
		if errors.Is(err, auth.ErrPasswordResetUnavailable) {
			return c.Status(fiber.StatusServiceUnavailable).
				JSON(fiber.Map{"error": "Password reset is not enabled on this server"})
		}
		// Mailer or DB failure — log it but still return the generic
		// success response so an unstable mailer can't be used to learn
		// which emails are registered. Operators see the failure in logs.
		log.Error().Err(err).Str("email", input.Email).Msg("ForgotPassword: backend error")
	}
	return c.JSON(ForgotPasswordResponse{Message: genericForgotPasswordMessage})
}

// ResetPassword completes the password-reset flow.
//
// @Summary      Reset password with a one-time token
// @Description  Consumes the token sent in the reset email, replaces the user's password, and rotates their refresh token so any active sessions are forced to re-authenticate.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      ResetPasswordRequest   true  "Token plus new password"
// @Success      200      {object}  ResetPasswordResponse
// @Failure      400      {object}  auth.ErrorResponse
// @Failure      503      {object}  auth.ErrorResponse  "Reset is not configured on this server"
// @Router       /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *fiber.Ctx) error {
	var input ResetPasswordRequest
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}
	if input.Token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Token is required"})
	}
	if len(input.NewPassword) < minPasswordLength {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("New password must be at least %d characters", minPasswordLength),
		})
	}
	if len(input.NewPassword) > maxPasswordLength {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("New password must be at most %d characters", maxPasswordLength),
		})
	}

	if err := h.authService.ResetPassword(input.Token, input.NewPassword); err != nil {
		if errors.Is(err, auth.ErrPasswordResetUnavailable) {
			return c.Status(fiber.StatusServiceUnavailable).
				JSON(fiber.Map{"error": "Password reset is not enabled on this server"})
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(ResetPasswordResponse{Message: "Password updated successfully"})
}
