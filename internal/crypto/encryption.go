package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

// EncryptData шифрует данные с использованием AES-256-GCM.
// Ключ должен быть длиной 32 байта (256 бит) для AES-256.
// Возвращает зашифрованные данные с префиксом nonce или ошибку в случае неудачи.
func EncryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData расшифровывает данные, зашифрованные функцией EncryptData.
// Ключ должен быть тем же, что использовался при шифровании.
// Возвращает расшифрованные данные или ошибку в случае неудачи.
func DecryptData(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DeriveKeyFromPassword создает ключ шифрования из пароля пользователя и соли.
// Использует SHA256 для создания 32-байтового ключа AES-256.
// Одинаковые пароль и соль всегда дают одинаковый ключ.
// В production рекомендуется использовать crypto/pbkdf2 для большей безопасности.
func DeriveKeyFromPassword(password string, salt []byte) []byte {
	// Создаем ключ из пароля и соли
	// В production можно использовать crypto/pbkdf2 для большей безопасности
	combined := append([]byte(password), salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// ConstantTimeCompare выполняет постоянное по времени сравнение двух слайсов байтов.
// Используется для предотвращения атак по времени при сравнении криптографических данных.
// Возвращает true, если слайсы идентичны, и false в противном случае.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
