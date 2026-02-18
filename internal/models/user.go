package models

// User представляет пользователя системы GophKeeper.
// Содержит информацию о пользователе, включая уникальный идентификатор,
// логин и хеш пароля.
type User struct {
	ID        int64  `json:"id"`         // Уникальный идентификатор пользователя
	Login     string `json:"login"`      // Логин пользователя
	Password  string `json:"-"`          // Хеш пароля, не сериализуется в JSON
	CreatedAt int64  `json:"created_at"` // Время создания пользователя (Unix timestamp)
}

// UserCredentials представляет учетные данные для регистрации или входа в систему.
// Используется при регистрации нового пользователя и аутентификации существующего.
type UserCredentials struct {
	Login    string `json:"login"`    // Логин пользователя
	Password string `json:"password"` // Пароль пользователя (в открытом виде)
}
