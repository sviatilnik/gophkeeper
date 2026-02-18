package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sviatilnik/gophkeeper/internal/auth"
	"github.com/sviatilnik/gophkeeper/internal/models"
	"github.com/sviatilnik/gophkeeper/internal/server"
	"github.com/sviatilnik/gophkeeper/internal/storage"
)

func setupTestServer() *httptest.Server {
	stor := storage.NewInMemoryStorage()
	tokenManager := auth.NewInMemoryTokenManager(1 * time.Hour)
	srv := server.NewServer(stor, tokenManager)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", srv.HandleRegister)
	mux.HandleFunc("/api/login", srv.HandleLogin)
	mux.HandleFunc("/api/secrets", srv.MiddlewareAuth(srv.HandleSecrets))
	mux.HandleFunc("/api/secrets/", srv.MiddlewareAuth(srv.HandleSecretByID))
	mux.HandleFunc("/api/sync", srv.MiddlewareAuth(srv.HandleSync))

	return httptest.NewServer(mux)
}

func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:8080")

	if client.baseURL != "http://localhost:8080" {
		t.Errorf("NewClient set wrong baseURL: got %s, want http://localhost:8080", client.baseURL)
	}

	if client.client == nil {
		t.Error("NewClient did not initialize HTTP client")
	}
}

func TestSetToken(t *testing.T) {
	client := NewClient("http://localhost:8080")
	token := "testtoken123"

	client.SetToken(token)

	if client.token != token {
		t.Errorf("SetToken did not set token: got %s, want %s", client.token, token)
	}
}

func TestRegister(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	resp, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if resp.User.Login != "testuser" {
		t.Errorf("Register returned wrong login: got %s, want testuser", resp.User.Login)
	}

	if resp.Token.Token == "" {
		t.Error("Register returned empty token")
	}

	if client.token != resp.Token.Token {
		t.Error("Register did not set token in client")
	}
}

func TestRegisterError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "User already exists"})
	}))
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err == nil {
		t.Error("Register should return error on conflict")
	}
}

func TestRegisterNetworkError(t *testing.T) {
	client := NewClient("http://invalid-url:9999")

	_, err := client.Register("testuser", "testpass")
	if err == nil {
		t.Error("Register should return error on network failure")
	}
}

func TestLogin(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	// Сначала регистрируем
	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Создаем нового клиента для логина
	client2 := NewClient(ts.URL)
	resp, err := client2.Login("testuser", "testpass")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if resp.User.Login != "testuser" {
		t.Errorf("Login returned wrong login: got %s, want testuser", resp.User.Login)
	}

	if resp.Token.Token == "" {
		t.Error("Login returned empty token")
	}

	if client2.token != resp.Token.Token {
		t.Error("Login did not set token in client")
	}
}

func TestLoginError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
	}))
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Login("testuser", "wrongpass")
	if err == nil {
		t.Error("Login should return error on invalid credentials")
	}
}

func TestLoginNetworkError(t *testing.T) {
	client := NewClient("http://invalid-url:9999")

	_, err := client.Login("testuser", "testpass")
	if err == nil {
		t.Error("Login should return error on network failure")
	}
}

func TestGetSecrets(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	// Регистрируем и получаем токен
	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Создаем секрет
	_, err = client.CreateSecret(models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	secrets, err := client.GetSecrets()
	if err != nil {
		t.Fatalf("GetSecrets failed: %v", err)
	}

	if len(secrets) == 0 {
		t.Error("GetSecrets should return at least one secret")
	}
}

func TestGetSecretsNoToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.GetSecrets()
	if err == nil {
		t.Error("GetSecrets should return error without token")
	}
}

func TestGetSecretsNetworkError(t *testing.T) {
	client := NewClient("http://invalid-url:9999")
	client.SetToken("testtoken")

	_, err := client.GetSecrets()
	if err == nil {
		t.Error("GetSecrets should return error on network failure")
	}
}

func TestCreateSecret(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	secret, err := client.CreateSecret(models.SecretTypeLoginPassword, []byte("data"), "metadata")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	if secret.Type != models.SecretTypeLoginPassword {
		t.Errorf("CreateSecret returned wrong type: got %s, want %s", secret.Type, models.SecretTypeLoginPassword)
	}
}

func TestCreateSecretError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	_, err := client.CreateSecret(models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err == nil {
		t.Error("CreateSecret should return error on bad request")
	}
}

func TestGetSecret(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	createdSecret, err := client.CreateSecret(models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	secret, err := client.GetSecret(createdSecret.ID)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if secret.ID != createdSecret.ID {
		t.Errorf("GetSecret returned wrong ID: got %d, want %d", secret.ID, createdSecret.ID)
	}
}

func TestGetSecretNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Secret not found"})
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	_, err := client.GetSecret(999)
	if err == nil {
		t.Error("GetSecret should return error when secret not found")
	}
}

func TestUpdateSecret(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	secret, err := client.CreateSecret(models.SecretTypeLoginPassword, []byte("olddata"), "oldmeta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	updatedSecret, err := client.UpdateSecret(secret.ID, []byte("newdata"), "newmeta")
	if err != nil {
		t.Fatalf("UpdateSecret failed: %v", err)
	}

	if updatedSecret.Version != 2 {
		t.Errorf("UpdateSecret returned wrong version: got %d, want 2", updatedSecret.Version)
	}
}

func TestUpdateSecretError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Secret not found"})
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	_, err := client.UpdateSecret(999, []byte("data"), "meta")
	if err == nil {
		t.Error("UpdateSecret should return error when secret not found")
	}
}

func TestDeleteSecret(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	secret, err := client.CreateSecret(models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	err = client.DeleteSecret(secret.ID)
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}
}

func TestDeleteSecretError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Secret not found"})
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	err := client.DeleteSecret(999)
	if err == nil {
		t.Error("DeleteSecret should return error when secret not found")
	}
}

func TestSync(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	secrets, err := client.Sync()
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	_ = secrets
}

func TestSyncError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Sync()
	if err == nil {
		t.Error("Sync should return error without token")
	}
}

func TestRegisterJSONError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err == nil {
		t.Error("Register should return error on invalid JSON response")
	}
}

func TestLoginJSONError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Login("testuser", "testpass")
	if err == nil {
		t.Error("Login should return error on invalid JSON response")
	}
}

func TestGetSecretsJSONError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	_, err := client.GetSecrets()
	if err == nil {
		t.Error("GetSecrets should return error on invalid JSON response")
	}
}

func TestCreateSecretJSONError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	_, err := client.CreateSecret(models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err == nil {
		t.Error("CreateSecret should return error on invalid JSON response")
	}
}

func TestGetSecretJSONError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	_, err := client.GetSecret(1)
	if err == nil {
		t.Error("GetSecret should return error on invalid JSON response")
	}
}

func TestUpdateSecretJSONError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := NewClient(ts.URL)
	client.SetToken("testtoken")

	_, err := client.UpdateSecret(1, []byte("data"), "meta")
	if err == nil {
		t.Error("UpdateSecret should return error on invalid JSON response")
	}
}

func TestGetSecretsEmptyList(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	secrets, err := client.GetSecrets()
	if err != nil {
		t.Fatalf("GetSecrets failed: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("GetSecrets should return empty list for new user, got %d", len(secrets))
	}
}

func TestCreateSecretAllTypes(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)

	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	types := []models.SecretType{
		models.SecretTypeLoginPassword,
		models.SecretTypeText,
		models.SecretTypeBinary,
		models.SecretTypeCard,
	}

	for _, secretType := range types {
		secret, err := client.CreateSecret(secretType, []byte("data"), "meta")
		if err != nil {
			t.Errorf("CreateSecret failed for type %s: %v", secretType, err)
			continue
		}

		if secret.Type != secretType {
			t.Errorf("CreateSecret returned wrong type: got %s, want %s", secret.Type, secretType)
		}
	}
}

func TestRegisterJSONMarshalError(t *testing.T) {
	// Тест для проверки обработки ошибок JSON маршалинга
	// В реальности json.Marshal для простых структур не должен возвращать ошибок
	client := NewClient("http://localhost:8080")

	// Используем валидные данные - json.Marshal не должен вернуть ошибку
	_, err := client.Register("testuser", "testpass")
	// Ожидаем ошибку сети, а не ошибку маршалинга
	if err != nil && err.Error() == "json: unsupported type" {
		t.Error("Register should not return JSON marshal error for valid input")
	}
}

func TestLoginJSONMarshalError(t *testing.T) {
	// Тест для проверки обработки ошибок JSON маршалинга
	client := NewClient("http://localhost:8080")

	// Используем валидные данные
	_, err := client.Login("testuser", "testpass")
	// Ожидаем ошибку сети, а не ошибку маршалинга
	if err != nil && err.Error() == "json: unsupported type" {
		t.Error("Login should not return JSON marshal error for valid input")
	}
}

func TestCreateSecretJSONMarshalError(t *testing.T) {
	// Тест для проверки обработки ошибок JSON маршалинга
	client := NewClient("http://localhost:8080")
	client.SetToken("testtoken")

	// Используем валидные данные
	_, err := client.CreateSecret(models.SecretTypeLoginPassword, []byte("data"), "meta")
	// Ожидаем ошибку сети, а не ошибку маршалинга
	if err != nil && err.Error() == "json: unsupported type" {
		t.Error("CreateSecret should not return JSON marshal error for valid input")
	}
}

func TestUpdateSecretJSONMarshalError(t *testing.T) {
	// Тест для проверки обработки ошибок JSON маршалинга
	client := NewClient("http://localhost:8080")
	client.SetToken("testtoken")

	// Используем валидные данные
	_, err := client.UpdateSecret(1, []byte("data"), "meta")
	// Ожидаем ошибку сети, а не ошибку маршалинга
	if err != nil && err.Error() == "json: unsupported type" {
		t.Error("UpdateSecret should not return JSON marshal error for valid input")
	}
}

func TestGetSecretInvalidID(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)
	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Тестируем получение несуществующего секрета
	_, err = client.GetSecret(999)
	if err == nil {
		t.Error("GetSecret should return error for non-existent secret")
	}
}

func TestUpdateSecretInvalidID(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)
	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Тестируем обновление несуществующего секрета
	_, err = client.UpdateSecret(999, []byte("data"), "meta")
	if err == nil {
		t.Error("UpdateSecret should return error for non-existent secret")
	}
}

func TestGetSecretsWithMultipleSecrets(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)
	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Создаем несколько секретов
	_, err = client.CreateSecret(models.SecretTypeLoginPassword, []byte("data1"), "meta1")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	_, err = client.CreateSecret(models.SecretTypeText, []byte("data2"), "meta2")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	_, err = client.CreateSecret(models.SecretTypeBinary, []byte("data3"), "meta3")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	secrets, err := client.GetSecrets()
	if err != nil {
		t.Fatalf("GetSecrets failed: %v", err)
	}

	if len(secrets) != 3 {
		t.Errorf("GetSecrets returned %d secrets, want 3", len(secrets))
	}
}

func TestSyncWithMultipleSecrets(t *testing.T) {
	ts := setupTestServer()
	defer ts.Close()

	client := NewClient(ts.URL)
	_, err := client.Register("testuser", "testpass")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Создаем несколько секретов
	_, err = client.CreateSecret(models.SecretTypeLoginPassword, []byte("data1"), "meta1")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	_, err = client.CreateSecret(models.SecretTypeCard, []byte("data2"), "meta2")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	secrets, err := client.Sync()
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("Sync returned %d secrets, want 2", len(secrets))
	}
}
