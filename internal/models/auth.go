package models

// AuthToken представляет токен аутентификации пользователя.
// Используется для авторизации запросов к защищенным эндпоинтам сервера.
type AuthToken struct {
	Token     string `json:"token"`      // Токен доступа
	ExpiresAt int64  `json:"expires_at"` // Время истечения токена (Unix timestamp, 0 если не установлено)
}

// AuthResponse представляет ответ на запрос аутентификации (регистрация или вход).
// Содержит токен доступа и информацию о пользователе.
type AuthResponse struct {
	Token AuthToken `json:"token"` // Токен аутентификации
	User  User      `json:"user"`  // Информация о пользователе
}
