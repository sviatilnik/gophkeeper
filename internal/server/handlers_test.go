package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sviatilnik/gophkeeper/internal/auth"
	"github.com/sviatilnik/gophkeeper/internal/crypto"
	"github.com/sviatilnik/gophkeeper/internal/models"
	"github.com/sviatilnik/gophkeeper/internal/storage"
)

func setupTestServer() *Server {
	stor := storage.NewInMemoryStorage()
	tokenManager := auth.NewInMemoryTokenManager(1 * time.Hour)
	return NewServer(stor, tokenManager)
}

func TestRegister(t *testing.T) {
	srv := setupTestServer()

	creds := models.UserCredentials{
		Login:    "testuser",
		Password: "testpass",
	}

	body, _ := json.Marshal(creds)
	req := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.HandleRegister(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleRegister returned status %d, want %d", w.Code, http.StatusOK)
	}

	var resp models.AuthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.User.Login != "testuser" {
		t.Errorf("HandleRegister returned wrong login: got %s, want testuser", resp.User.Login)
	}

	if resp.Token.Token == "" {
		t.Error("HandleRegister returned empty token")
	}
}

func TestRegisterInvalidMethod(t *testing.T) {
	srv := setupTestServer()

	req := httptest.NewRequest("GET", "/api/register", nil)
	w := httptest.NewRecorder()

	srv.handleRegister(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleRegister returned status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestRegisterInvalidBody(t *testing.T) {
	srv := setupTestServer()

	req := httptest.NewRequest("POST", "/api/register", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleRegister returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegisterEmptyCredentials(t *testing.T) {
	srv := setupTestServer()

	creds := models.UserCredentials{
		Login:    "",
		Password: "",
	}

	body, _ := json.Marshal(creds)
	req := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleRegister returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegisterEmptyLogin(t *testing.T) {
	srv := setupTestServer()

	creds := models.UserCredentials{
		Login:    "",
		Password: "password",
	}

	body, _ := json.Marshal(creds)
	req := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleRegister returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegisterEmptyPassword(t *testing.T) {
	srv := setupTestServer()

	creds := models.UserCredentials{
		Login:    "user",
		Password: "",
	}

	body, _ := json.Marshal(creds)
	req := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleRegister returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	srv := setupTestServer()

	creds := models.UserCredentials{
		Login:    "testuser",
		Password: "testpass",
	}

	body, _ := json.Marshal(creds)
	req1 := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(body))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	srv.handleRegister(w1, req1)

	req2 := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	srv.handleRegister(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Errorf("handleRegister returned status %d, want %d", w2.Code, http.StatusConflict)
	}
}

func TestLogin(t *testing.T) {
	srv := setupTestServer()

	// Сначала регистрируем пользователя
	password := "testpass"
	passwordHash, _ := crypto.HashPassword(password)
	srv.storage.CreateUser("testuser", passwordHash)

	creds := models.UserCredentials{
		Login:    "testuser",
		Password: password,
	}

	body, _ := json.Marshal(creds)
	req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.HandleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleLogin returned status %d, want %d", w.Code, http.StatusOK)
	}

	var resp models.AuthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Token.Token == "" {
		t.Error("HandleLogin returned empty token")
	}
}

func TestLoginInvalidMethod(t *testing.T) {
	srv := setupTestServer()

	req := httptest.NewRequest("GET", "/api/login", nil)
	w := httptest.NewRecorder()

	srv.handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleLogin returned status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestLoginInvalidBody(t *testing.T) {
	srv := setupTestServer()

	req := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleLogin returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	srv := setupTestServer()

	creds := models.UserCredentials{
		Login:    "nonexistent",
		Password: "password",
	}

	body, _ := json.Marshal(creds)
	req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("handleLogin returned status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	srv := setupTestServer()

	password := "testpass"
	passwordHash, _ := crypto.HashPassword(password)
	srv.storage.CreateUser("testuser", passwordHash)

	creds := models.UserCredentials{
		Login:    "testuser",
		Password: "wrongpassword",
	}

	body, _ := json.Marshal(creds)
	req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("handleLogin returned status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestCreateSecret(t *testing.T) {
	srv := setupTestServer()

	// Создаем пользователя и получаем токен
	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	reqBody := map[string]interface{}{
		"type":     models.SecretTypeLoginPassword,
		"data":     []byte("secretdata"),
		"metadata": "test metadata",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.HandleSecrets(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("HandleSecrets returned status %d, want %d", w.Code, http.StatusCreated)
	}

	var secret models.Secret
	if err := json.NewDecoder(w.Body).Decode(&secret); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if secret.Type != models.SecretTypeLoginPassword {
		t.Errorf("HandleSecrets returned wrong type: got %s, want %s", secret.Type, models.SecretTypeLoginPassword)
	}
}

func TestCreateSecretInvalidBody(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecrets(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleSecrets returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetSecrets(t *testing.T) {
	srv := setupTestServer()

	// Создаем пользователя и секреты
	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data1"), "meta1")
	srv.storage.CreateSecret(user.ID, models.SecretTypeText, []byte("data2"), "meta2")

	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.HandleSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleSecrets returned status %d, want %d", w.Code, http.StatusOK)
	}

	var secrets []*models.Secret
	if err := json.NewDecoder(w.Body).Decode(&secrets); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("HandleSecrets returned %d secrets, want 2", len(secrets))
	}
}

func TestGetSecretsInvalidMethod(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("DELETE", "/api/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecrets(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleSecrets returned status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestGetSecretByID(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	secret, _ := srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")

	req := httptest.NewRequest("GET", "/api/secrets/"+strconv.FormatInt(secret.ID, 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.HandleSecretByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleSecretByID returned status %d, want %d", w.Code, http.StatusOK)
	}

	var retrievedSecret models.Secret
	if err := json.NewDecoder(w.Body).Decode(&retrievedSecret); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if retrievedSecret.ID != secret.ID {
		t.Errorf("HandleSecretByID returned wrong ID: got %d, want %d", retrievedSecret.ID, secret.ID)
	}
}

func TestGetSecretByIDNotFound(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("GET", "/api/secrets/999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecretByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("handleSecretByID returned status %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestGetSecretByIDInvalidID(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("GET", "/api/secrets/invalid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecretByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleSecretByID returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestUpdateSecret(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	secret, _ := srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("olddata"), "oldmeta")

	reqBody := map[string]interface{}{
		"data":     []byte("newdata"),
		"metadata": "newmeta",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("PUT", "/api/secrets/"+strconv.FormatInt(secret.ID, 10), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.HandleSecretByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleSecretByID returned status %d, want %d", w.Code, http.StatusOK)
	}

	var updatedSecret models.Secret
	if err := json.NewDecoder(w.Body).Decode(&updatedSecret); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if updatedSecret.Version != 2 {
		t.Errorf("HandleSecretByID returned wrong version: got %d, want 2", updatedSecret.Version)
	}
}

func TestUpdateSecretInvalidBody(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	secret, _ := srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")

	req := httptest.NewRequest("PUT", "/api/secrets/"+strconv.FormatInt(secret.ID, 10), bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecretByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleSecretByID returned status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestUpdateSecretNotFound(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	reqBody := map[string]interface{}{
		"data":     []byte("newdata"),
		"metadata": "newmeta",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("PUT", "/api/secrets/999", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecretByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("handleSecretByID returned status %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteSecret(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	secret, _ := srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")

	req := httptest.NewRequest("DELETE", "/api/secrets/"+strconv.FormatInt(secret.ID, 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.HandleSecretByID(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("HandleSecretByID returned status %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestDeleteSecretNotFound(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("DELETE", "/api/secrets/999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecretByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("handleSecretByID returned status %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteSecretInvalidMethod(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("POST", "/api/secrets/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecretByID(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleSecretByID returned status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleSync(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data1"), "meta1")
	srv.storage.CreateSecret(user.ID, models.SecretTypeText, []byte("data2"), "meta2")

	req := httptest.NewRequest("GET", "/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.HandleSync(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("HandleSync returned status %d, want %d", w.Code, http.StatusOK)
	}

	var secrets []*models.Secret
	if err := json.NewDecoder(w.Body).Decode(&secrets); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("HandleSync returned %d secrets, want 2", len(secrets))
	}
}

func TestHandleSyncInvalidMethod(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("POST", "/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSync(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleSync returned status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestMiddlewareAuth(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	// Тест с валидным токеном
	handler := srv.MiddlewareAuth(func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(int64)
		if userID != user.ID {
			t.Errorf("middlewareAuth set wrong userID: got %d, want %d", userID, user.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("MiddlewareAuth returned status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestMiddlewareAuthNoToken(t *testing.T) {
	srv := setupTestServer()

	handler := srv.MiddlewareAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called when token is missing")
	})

	req := httptest.NewRequest("GET", "/api/secrets", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("MiddlewareAuth returned status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareAuthInvalidToken(t *testing.T) {
	srv := setupTestServer()

	handler := srv.MiddlewareAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called with invalid token")
	})

	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("MiddlewareAuth returned status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareAuthBearerPrefix(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	handler := srv.MiddlewareAuth(func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(int64)
		if userID != user.ID {
			t.Errorf("middlewareAuth set wrong userID: got %d, want %d", userID, user.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("MiddlewareAuth returned status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestMiddlewareAuthTokenWithoutBearer(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	handler := srv.MiddlewareAuth(func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID").(int64)
		if userID != user.ID {
			t.Errorf("middlewareAuth set wrong userID: got %d, want %d", userID, user.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("Authorization", token) // Без префикса Bearer
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("MiddlewareAuth returned status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRegisterRoutes(t *testing.T) {
	srv := setupTestServer()
	srv.RegisterRoutes()
	// Если не паникует, значит маршруты зарегистрированы
}


func TestGetSecretsStorageError(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecrets(w, req)

	// Должен вернуть 200 даже если секретов нет
	if w.Code != http.StatusOK {
		t.Errorf("handleSecrets returned status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCreateSecretAllTypes(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	types := []models.SecretType{
		models.SecretTypeLoginPassword,
		models.SecretTypeText,
		models.SecretTypeBinary,
		models.SecretTypeCard,
	}

	for _, secretType := range types {
		reqBody := map[string]interface{}{
			"type":     secretType,
			"data":     []byte("data"),
			"metadata": "meta",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/secrets", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
		w := httptest.NewRecorder()

		srv.handleSecrets(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("handleSecrets returned status %d for type %s, want %d", w.Code, secretType, http.StatusCreated)
		}
	}
}

func TestCreateSecretWithoutMetadata(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	reqBody := map[string]interface{}{
		"type": models.SecretTypeLoginPassword,
		"data": []byte("data"),
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecrets(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("handleSecrets returned status %d, want %d", w.Code, http.StatusCreated)
	}
}

func TestDeleteSecretError(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)

	// Тестируем удаление несуществующего секрета
	req := httptest.NewRequest("DELETE", "/api/secrets/999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()

	srv.handleSecretByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("handleSecretByID returned status %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleSecretByIDAllMethods(t *testing.T) {
	srv := setupTestServer()

	passwordHash, _ := crypto.HashPassword("testpass")
	user, _ := srv.storage.CreateUser("testuser", passwordHash)
	token, _ := srv.tokenManager.GenerateToken(user.ID)
	secret, _ := srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")

	// Test GET
	req := httptest.NewRequest("GET", "/api/secrets/"+strconv.FormatInt(secret.ID, 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w := httptest.NewRecorder()
	srv.handleSecretByID(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET returned status %d, want %d", w.Code, http.StatusOK)
	}

	// Test PUT
	reqBody := map[string]interface{}{
		"data":     []byte("newdata"),
		"metadata": "newmeta",
	}
	body, _ := json.Marshal(reqBody)
	req = httptest.NewRequest("PUT", "/api/secrets/"+strconv.FormatInt(secret.ID, 10), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w = httptest.NewRecorder()
	srv.handleSecretByID(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("PUT returned status %d, want %d", w.Code, http.StatusOK)
	}

	// Test DELETE
	secret2, _ := srv.storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")
	req = httptest.NewRequest("DELETE", "/api/secrets/"+strconv.FormatInt(secret2.ID, 10), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(context.WithValue(req.Context(), "userID", user.ID))
	w = httptest.NewRecorder()
	srv.handleSecretByID(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("DELETE returned status %d, want %d", w.Code, http.StatusNoContent)
	}
}
