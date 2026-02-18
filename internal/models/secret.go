package models

import "time"

// SecretType определяет тип хранимых секретных данных
type SecretType string

const (
	// SecretTypeLoginPassword - пара логин/пароль
	SecretTypeLoginPassword SecretType = "login_password"
	// SecretTypeText - произвольные текстовые данные
	SecretTypeText SecretType = "text"
	// SecretTypeBinary - произвольные бинарные данные
	SecretTypeBinary SecretType = "binary"
	// SecretTypeCard - данные банковской карты
	SecretTypeCard SecretType = "card"
)

// Secret представляет секретное данное, хранимое в системе
type Secret struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	Type      SecretType `json:"type"`
	Data      []byte     `json:"data"`     // Зашифрованные данные
	Metadata  string     `json:"metadata"` // Произвольная текстовая метаинформация
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Version   int64      `json:"version"` // Версия для синхронизации
}

// SecretData представляет расшифрованные данные секрета
// Используется на клиенте для работы с данными
type SecretData struct {
	ID        int64      `json:"id"`
	Type      SecretType `json:"type"`
	Data      []byte     `json:"data"` // Расшифрованные данные
	Metadata  string     `json:"metadata"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Version   int64      `json:"version"`
}
