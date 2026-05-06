package repository

import (
	"bedrud/internal/models"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PasswordResetTokenRepository persists one-time password reset tokens.
//
// The plaintext token is returned only from Create — at-rest we store the
// SHA-256 hex digest so a database leak cannot be replayed against the
// reset endpoint.
type PasswordResetTokenRepository struct {
	db *gorm.DB
}

func NewPasswordResetTokenRepository(db *gorm.DB) *PasswordResetTokenRepository {
	return &PasswordResetTokenRepository{db: db}
}

// HashResetToken returns the canonical at-rest representation of a reset
// token (SHA-256 hex). Exposed for callers that need to look up a token
// without going through Create (e.g. ResetPassword handlers).
func HashResetToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Create generates a fresh URL-safe secret, stores its hash with the given
// TTL, and returns the plaintext secret to be emailed to the user. Any
// existing un-used tokens for the same user are invalidated first so a
// stolen-then-superseded link cannot be replayed.
func (r *PasswordResetTokenRepository) Create(userID string, ttl time.Duration) (plaintext string, _ *models.PasswordResetToken, err error) {
	if userID == "" {
		return "", nil, errors.New("userID is required")
	}
	if ttl <= 0 {
		return "", nil, errors.New("ttl must be positive")
	}

	if err := r.InvalidateForUser(userID); err != nil {
		return "", nil, err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	plaintext = base64.RawURLEncoding.EncodeToString(raw)

	rec := &models.PasswordResetToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     HashResetToken(plaintext),
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := r.db.Create(rec).Error; err != nil {
		return "", nil, err
	}
	return plaintext, rec, nil
}

// GetByPlaintext looks up an active token by its plaintext value. Returns
// (nil, nil) when no matching unused, unexpired record exists — callers
// should treat that as "invalid token" and respond with a generic error
// to avoid leaking which half of the check failed.
func (r *PasswordResetTokenRepository) GetByPlaintext(plaintext string) (*models.PasswordResetToken, error) {
	if plaintext == "" {
		return nil, nil
	}
	var t models.PasswordResetToken
	err := r.db.Where("token = ? AND used_at IS NULL AND expires_at > ?", HashResetToken(plaintext), time.Now()).First(&t).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// MarkUsed records a successful redemption. The CAS-style WHERE clause
// guarantees a token can only be redeemed once even under concurrent
// requests.
func (r *PasswordResetTokenRepository) MarkUsed(tokenID string) error {
	now := time.Now()
	result := r.db.Model(&models.PasswordResetToken{}).
		Where("id = ? AND used_at IS NULL", tokenID).
		Update("used_at", now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("token already used or not found")
	}
	return nil
}

// InvalidateForUser deletes all outstanding (unused) tokens for a user.
// Called both when issuing a fresh token and after a successful reset to
// keep the table tidy.
func (r *PasswordResetTokenRepository) InvalidateForUser(userID string) error {
	return r.db.Where("user_id = ? AND used_at IS NULL", userID).
		Delete(&models.PasswordResetToken{}).Error
}

// CleanupExpired removes records whose lifetime has elapsed. Safe to run
// from a periodic background job.
func (r *PasswordResetTokenRepository) CleanupExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).
		Delete(&models.PasswordResetToken{}).Error
}
