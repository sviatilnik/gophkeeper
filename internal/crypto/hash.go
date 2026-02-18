package crypto

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword создает bcrypt хеш пароля
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPassword проверяет соответствие пароля хешу
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashSHA256 создает SHA256 хеш из данных
func HashSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
