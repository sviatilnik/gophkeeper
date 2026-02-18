package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sviatilnik/gophkeeper/internal/auth"
	"github.com/sviatilnik/gophkeeper/internal/crypto"
	"github.com/sviatilnik/gophkeeper/internal/models"
	"github.com/sviatilnik/gophkeeper/internal/storage"
)

// Server представляет HTTP сервер GophKeeper.
// Обрабатывает запросы от клиентов и взаимодействует с хранилищем данных.
type Server struct {
	storage      storage.Storage      // Хранилище данных пользователей и секретов
	tokenManager auth.TokenManager    // Менеджер токенов аутентификации
}

// NewServer создает новый экземпляр HTTP сервера GophKeeper.
// Принимает хранилище данных и менеджер токенов для инициализации.
func NewServer(storage storage.Storage, tokenManager auth.TokenManager) *Server {
	return &Server{
		storage:      storage,
		tokenManager: tokenManager,
	}
}

// RegisterRoutes регистрирует все HTTP маршруты сервера.
// Регистрирует эндпоинты для регистрации, входа, работы с секретами и синхронизации.
func (s *Server) RegisterRoutes() {
	http.HandleFunc("/api/register", s.handleRegister)
	http.HandleFunc("/api/login", s.handleLogin)
	http.HandleFunc("/api/secrets", s.middlewareAuth(s.handleSecrets))
	http.HandleFunc("/api/secrets/", s.middlewareAuth(s.handleSecretByID))
	http.HandleFunc("/api/sync", s.middlewareAuth(s.handleSync))
}

// HandleRegister обрабатывает HTTP запрос на регистрацию нового пользователя.
// Экспортируется для тестирования.
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	s.handleRegister(w, r)
}

// handleRegister обрабатывает регистрацию нового пользователя
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds models.UserCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if creds.Login == "" || creds.Password == "" {
		http.Error(w, "Login and password are required", http.StatusBadRequest)
		return
	}

	passwordHash, err := crypto.HashPassword(creds.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user, err := s.storage.CreateUser(creds.Login, passwordHash)
	if err != nil {
		if err == storage.ErrUserExists {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Автоматически логиним пользователя после регистрации
	token, err := s.tokenManager.GenerateToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := models.AuthResponse{
		Token: models.AuthToken{
			Token:     token,
			ExpiresAt: 0, // Можно добавить реальное время истечения
		},
		User: *user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleLogin обрабатывает HTTP запрос на вход пользователя в систему.
// Экспортируется для тестирования.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	s.handleLogin(w, r)
}

// handleLogin обрабатывает HTTP запрос на вход пользователя в систему.
// Ожидает POST запрос с JSON телом, содержащим логин и пароль.
// Возвращает токен аутентификации при успешной проверке учетных данных.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds models.UserCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.storage.GetUserByLogin(creds.Login)
	if err != nil {
		if err == storage.ErrUserNotFound {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !crypto.CheckPassword(creds.Password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := s.tokenManager.GenerateToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := models.AuthResponse{
		Token: models.AuthToken{
			Token:     token,
			ExpiresAt: 0,
		},
		User: *user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleSecrets обрабатывает HTTP запросы для работы со списком секретов пользователя.
// Экспортируется для тестирования.
func (s *Server) HandleSecrets(w http.ResponseWriter, r *http.Request) {
	s.handleSecrets(w, r)
}

// handleSecrets обрабатывает HTTP запросы для работы со списком секретов пользователя.
// Поддерживает GET (получение всех секретов) и POST (создание нового секрета).
// Требует валидный токен аутентификации в заголовке Authorization.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int64)

	switch r.Method {
	case http.MethodGet:
		secrets, err := s.storage.GetUserSecrets(userID)
		if err != nil {
			http.Error(w, "Failed to get secrets", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(secrets)

	case http.MethodPost:
		var req struct {
			Type     models.SecretType `json:"type"`
			Data     []byte            `json:"data"`
			Metadata string            `json:"metadata"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		secret, err := s.storage.CreateSecret(userID, req.Type, req.Data, req.Metadata)
		if err != nil {
			http.Error(w, "Failed to create secret", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(secret)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleSecretByID обрабатывает HTTP запросы для работы с конкретным секретом по ID.
// Экспортируется для тестирования.
func (s *Server) HandleSecretByID(w http.ResponseWriter, r *http.Request) {
	s.handleSecretByID(w, r)
}

// handleSecretByID обрабатывает HTTP запросы для работы с конкретным секретом по ID.
// Поддерживает GET (получение), PUT (обновление) и DELETE (удаление).
// ID секрета извлекается из пути запроса.
// Требует валидный токен аутентификации в заголовке Authorization.
func (s *Server) handleSecretByID(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(int64)

	// Извлекаем ID из пути /api/secrets/{id}
	path := r.URL.Path
	secretIDStr := path[len("/api/secrets/"):]
	secretID, err := strconv.ParseInt(secretIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid secret ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		secret, err := s.storage.GetSecretByID(userID, secretID)
		if err != nil {
			if err == storage.ErrSecretNotFound {
				http.Error(w, "Secret not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to get secret", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(secret)

	case http.MethodPut:
		var req struct {
			Data     []byte `json:"data"`
			Metadata string `json:"metadata"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		secret, err := s.storage.UpdateSecret(userID, secretID, req.Data, req.Metadata)
		if err != nil {
			if err == storage.ErrSecretNotFound {
				http.Error(w, "Secret not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to update secret", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(secret)

	case http.MethodDelete:
		if err := s.storage.DeleteSecret(userID, secretID); err != nil {
			if err == storage.ErrSecretNotFound {
				http.Error(w, "Secret not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to delete secret", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleSync обрабатывает HTTP запрос на синхронизацию данных пользователя.
// Экспортируется для тестирования.
func (s *Server) HandleSync(w http.ResponseWriter, r *http.Request) {
	s.handleSync(w, r)
}

// handleSync обрабатывает HTTP запрос на синхронизацию данных пользователя.
// Возвращает все секреты пользователя для синхронизации между клиентами.
// Требует валидный токен аутентификации в заголовке Authorization.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("userID").(int64)

	secrets, err := s.storage.GetUserSecrets(userID)
	if err != nil {
		http.Error(w, "Failed to sync secrets", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secrets)
}

// MiddlewareAuth является middleware для проверки аутентификации пользователя.
// Экспортируется для тестирования.
func (s *Server) MiddlewareAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.middlewareAuth(next)
}

// middlewareAuth является middleware для проверки аутентификации пользователя.
// Извлекает токен из заголовка Authorization, проверяет его валидность
// и добавляет ID пользователя в контекст запроса для использования в обработчиках.
// Возвращает HTTP 401, если токен отсутствует, невалиден или истек.
func (s *Server) middlewareAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Убираем префикс "Bearer " если он есть
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		userID, err := s.tokenManager.ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Добавляем userID в контекст
		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", userID)
		r = r.WithContext(ctx)

		next(w, r)
	}
}
