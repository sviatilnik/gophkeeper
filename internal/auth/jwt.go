package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	// ErrTokenExpired возвращается когда токен истек
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenInvalid возвращается когда токен невалиден
	ErrTokenInvalid = errors.New("invalid token")
)

// TokenManager управляет токенами аутентификации
type TokenManager interface {
	GenerateToken(userID int64) (string, error)
	ValidateToken(token string) (int64, error)
}

// InMemoryTokenManager реализует управление токенами в памяти
type InMemoryTokenManager struct {
	mu          sync.RWMutex
	tokens      map[string]*tokenInfo
	tokenExpiry time.Duration
}

type tokenInfo struct {
	userID    int64
	expiresAt time.Time
}

// NewInMemoryTokenManager создает новый менеджер токенов
func NewInMemoryTokenManager(tokenExpiry time.Duration) *InMemoryTokenManager {
	return &InMemoryTokenManager{
		tokens:      make(map[string]*tokenInfo),
		tokenExpiry: tokenExpiry,
	}
}

// GenerateToken генерирует новый токен для пользователя
func (tm *InMemoryTokenManager) GenerateToken(userID int64) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)

	tm.mu.Lock()
	tm.tokens[token] = &tokenInfo{
		userID:    userID,
		expiresAt: time.Now().Add(tm.tokenExpiry),
	}
	tm.mu.Unlock()

	return token, nil
}

// ValidateToken проверяет валидность токена и возвращает ID пользователя.
// Проверяет существование токена и его срок действия.
// Возвращает ErrTokenExpired, если токен истек, или ErrTokenInvalid, если токен не найден.
func (tm *InMemoryTokenManager) ValidateToken(token string) (int64, error) {
	tm.mu.RLock()
	info, exists := tm.tokens[token]
	tm.mu.RUnlock()

	if !exists {
		return 0, ErrTokenInvalid
	}

	if time.Now().After(info.expiresAt) {
		tm.mu.Lock()
		delete(tm.tokens, token)
		tm.mu.Unlock()
		return 0, ErrTokenExpired
	}

	return info.userID, nil
}
