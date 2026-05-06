package repository

import (
	"bedrud/internal/models"
	"bedrud/internal/testutil"
	"testing"
	"time"
)

func newResetUser(t *testing.T, repo *UserRepository, email string) *models.User {
	t.Helper()
	u := &models.User{
		ID:       email + "-id",
		Email:    email,
		Name:     "Reset User",
		Provider: models.ProviderLocal,
		IsActive: true,
		Password: "hashed",
		Accesses: models.StringArray{"user"},
	}
	if err := repo.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestPasswordResetTokenRepository_Create_ReturnsPlaintextAndStoresHash(t *testing.T) {
	db := testutil.SetupTestDB(t)
	users := NewUserRepository(db)
	resets := NewPasswordResetTokenRepository(db)
	u := newResetUser(t, users, "create@example.com")

	plain, rec, err := resets.Create(u.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if plain == "" {
		t.Fatal("expected non-empty plaintext")
	}
	if rec.Token == plain {
		t.Fatal("token must be stored hashed, not in plaintext")
	}
	if rec.Token != HashResetToken(plain) {
		t.Fatal("stored token must be SHA-256 of plaintext")
	}
	if rec.UserID != u.ID {
		t.Fatalf("expected userID %s, got %s", u.ID, rec.UserID)
	}
	if rec.UsedAt != nil {
		t.Fatal("expected new token to be unused")
	}
	if !rec.ExpiresAt.After(time.Now()) {
		t.Fatal("expected token to expire in the future")
	}
}

func TestPasswordResetTokenRepository_Create_InvalidatesPriorTokens(t *testing.T) {
	db := testutil.SetupTestDB(t)
	users := NewUserRepository(db)
	resets := NewPasswordResetTokenRepository(db)
	u := newResetUser(t, users, "rotate@example.com")

	first, _, err := resets.Create(u.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, _, err := resets.Create(u.ID, 15*time.Minute); err != nil {
		t.Fatalf("second create: %v", err)
	}

	// First token must no longer be redeemable.
	got, err := resets.GetByPlaintext(first)
	if err != nil {
		t.Fatalf("lookup first: %v", err)
	}
	if got != nil {
		t.Fatal("expected the prior token to be invalidated when a new one is issued")
	}
}

func TestPasswordResetTokenRepository_GetByPlaintext_ExpiredOrUsedReturnsNil(t *testing.T) {
	db := testutil.SetupTestDB(t)
	users := NewUserRepository(db)
	resets := NewPasswordResetTokenRepository(db)
	u := newResetUser(t, users, "expired@example.com")

	// Insert a manually expired token.
	expired := &models.PasswordResetToken{
		ID:        "expired-id",
		UserID:    u.ID,
		Token:     HashResetToken("expired-plain"),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := db.Create(expired).Error; err != nil {
		t.Fatalf("seed expired: %v", err)
	}
	got, err := resets.GetByPlaintext("expired-plain")
	if err != nil {
		t.Fatalf("lookup expired: %v", err)
	}
	if got != nil {
		t.Fatal("expected expired token to be ignored")
	}

	// Insert a used token.
	used := time.Now()
	usedRec := &models.PasswordResetToken{
		ID:        "used-id",
		UserID:    u.ID,
		Token:     HashResetToken("used-plain"),
		ExpiresAt: time.Now().Add(time.Hour),
		UsedAt:    &used,
	}
	if err := db.Create(usedRec).Error; err != nil {
		t.Fatalf("seed used: %v", err)
	}
	got, err = resets.GetByPlaintext("used-plain")
	if err != nil {
		t.Fatalf("lookup used: %v", err)
	}
	if got != nil {
		t.Fatal("expected used token to be ignored")
	}
}

func TestPasswordResetTokenRepository_MarkUsed_OnceOnly(t *testing.T) {
	db := testutil.SetupTestDB(t)
	users := NewUserRepository(db)
	resets := NewPasswordResetTokenRepository(db)
	u := newResetUser(t, users, "markused@example.com")

	plain, rec, err := resets.Create(u.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := resets.MarkUsed(rec.ID); err != nil {
		t.Fatalf("first MarkUsed: %v", err)
	}
	if err := resets.MarkUsed(rec.ID); err == nil {
		t.Fatal("expected second MarkUsed to fail (single-use)")
	}

	// And it must no longer be returned by lookup.
	if got, _ := resets.GetByPlaintext(plain); got != nil {
		t.Fatal("used token must not be returned by GetByPlaintext")
	}
}

func TestPasswordResetTokenRepository_CleanupExpired(t *testing.T) {
	db := testutil.SetupTestDB(t)
	users := NewUserRepository(db)
	resets := NewPasswordResetTokenRepository(db)
	u := newResetUser(t, users, "cleanup@example.com")

	if err := db.Create(&models.PasswordResetToken{
		ID:        "alive",
		UserID:    u.ID,
		Token:     HashResetToken("alive"),
		ExpiresAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("seed alive: %v", err)
	}
	if err := db.Create(&models.PasswordResetToken{
		ID:        "dead",
		UserID:    u.ID,
		Token:     HashResetToken("dead"),
		ExpiresAt: time.Now().Add(-time.Hour),
	}).Error; err != nil {
		t.Fatalf("seed dead: %v", err)
	}

	if err := resets.CleanupExpired(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var count int64
	db.Model(&models.PasswordResetToken{}).Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 surviving token, got %d", count)
	}
}

func TestPasswordResetTokenRepository_Create_RejectsBadInput(t *testing.T) {
	db := testutil.SetupTestDB(t)
	resets := NewPasswordResetTokenRepository(db)

	if _, _, err := resets.Create("", time.Minute); err == nil {
		t.Fatal("expected error for empty userID")
	}
	if _, _, err := resets.Create("any", 0); err == nil {
		t.Fatal("expected error for zero TTL")
	}
}
