package auth

import (
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	tm := NewInMemoryTokenManager(1 * time.Hour)

	userID := int64(123)
	token, err := tm.GenerateToken(userID)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == "" {
		t.Error("GenerateToken returned empty token")
	}
}

func TestValidateToken(t *testing.T) {
	tm := NewInMemoryTokenManager(1 * time.Hour)

	userID := int64(123)
	token, err := tm.GenerateToken(userID)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	validatedUserID, err := tm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if validatedUserID != userID {
		t.Errorf("ValidateToken returned wrong userID: got %d, want %d", validatedUserID, userID)
	}
}

func TestValidateTokenInvalid(t *testing.T) {
	tm := NewInMemoryTokenManager(1 * time.Hour)

	_, err := tm.ValidateToken("invalidtoken")
	if err != ErrTokenInvalid {
		t.Errorf("ValidateToken should return ErrTokenInvalid: got %v", err)
	}
}

func TestValidateTokenExpired(t *testing.T) {
	tm := NewInMemoryTokenManager(100 * time.Millisecond)

	userID := int64(123)
	token, err := tm.GenerateToken(userID)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Wait for token to expire
	time.Sleep(150 * time.Millisecond)

	_, err = tm.ValidateToken(token)
	if err != ErrTokenExpired {
		t.Errorf("ValidateToken should return ErrTokenExpired: got %v", err)
	}
}
