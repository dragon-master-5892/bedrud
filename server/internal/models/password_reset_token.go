package models

import "time"

// PasswordResetToken records a one-time secret a user can present to reset
// their password without being logged in. The Token column stores the
// SHA-256 hex digest of the secret — the plaintext value is only ever
// emailed to the user and never written to the database, so a database
// leak alone cannot grant account access.
type PasswordResetToken struct {
	ID        string     `gorm:"primaryKey;type:varchar(36)" json:"id"`
	UserID    string     `gorm:"not null;type:varchar(36);index" json:"userId"`
	Token     string     `gorm:"uniqueIndex;not null;type:varchar(64)" json:"-"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `gorm:"autoCreateTime;not null" json:"createdAt"`
}

// TableName specifies the table name for GORM.
func (PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}
