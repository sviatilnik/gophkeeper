package storage

import (
	"testing"

	"github.com/sviatilnik/gophkeeper/internal/models"
)

func TestCreateUser(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if user.Login != "testuser" {
		t.Errorf("CreateUser returned wrong login: got %s, want testuser", user.Login)
	}

	if user.ID == 0 {
		t.Error("CreateUser returned user with zero ID")
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	storage := NewInMemoryStorage()

	_, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	_, err = storage.CreateUser("testuser", "anotherpassword")
	if err != ErrUserExists {
		t.Errorf("CreateUser should return ErrUserExists for duplicate: got %v", err)
	}
}

func TestGetUserByLogin(t *testing.T) {
	storage := NewInMemoryStorage()

	createdUser, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	user, err := storage.GetUserByLogin("testuser")
	if err != nil {
		t.Fatalf("GetUserByLogin failed: %v", err)
	}

	if user.ID != createdUser.ID {
		t.Errorf("GetUserByLogin returned wrong user ID: got %d, want %d", user.ID, createdUser.ID)
	}
}

func TestGetUserByLoginNotFound(t *testing.T) {
	storage := NewInMemoryStorage()

	_, err := storage.GetUserByLogin("nonexistent")
	if err != ErrUserNotFound {
		t.Errorf("GetUserByLogin should return ErrUserNotFound: got %v", err)
	}
}

func TestGetUserByID(t *testing.T) {
	storage := NewInMemoryStorage()

	createdUser, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	user, err := storage.GetUserByID(createdUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}

	if user.Login != "testuser" {
		t.Errorf("GetUserByID returned wrong login: got %s, want testuser", user.Login)
	}
}

func TestGetUserByIDNotFound(t *testing.T) {
	storage := NewInMemoryStorage()

	_, err := storage.GetUserByID(999)
	if err != ErrUserNotFound {
		t.Errorf("GetUserByID should return ErrUserNotFound: got %v", err)
	}
}

func TestCreateSecret(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	secret, err := storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("secretdata"), "metadata")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	if secret.UserID != user.ID {
		t.Errorf("CreateSecret returned wrong UserID: got %d, want %d", secret.UserID, user.ID)
	}

	if secret.Type != models.SecretTypeLoginPassword {
		t.Errorf("CreateSecret returned wrong type: got %s, want %s", secret.Type, models.SecretTypeLoginPassword)
	}

	if secret.Version != 1 {
		t.Errorf("CreateSecret returned wrong version: got %d, want 1", secret.Version)
	}
}

func TestGetSecretByID(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	createdSecret, err := storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	secret, err := storage.GetSecretByID(user.ID, createdSecret.ID)
	if err != nil {
		t.Fatalf("GetSecretByID failed: %v", err)
	}

	if secret.ID != createdSecret.ID {
		t.Errorf("GetSecretByID returned wrong ID: got %d, want %d", secret.ID, createdSecret.ID)
	}
}

func TestGetSecretByIDNotFound(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	_, err = storage.GetSecretByID(user.ID, 999)
	if err != ErrSecretNotFound {
		t.Errorf("GetSecretByID should return ErrSecretNotFound: got %v", err)
	}
}

func TestGetSecretByIDWrongUser(t *testing.T) {
	storage := NewInMemoryStorage()

	user1, err := storage.CreateUser("user1", "hash1")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	user2, err := storage.CreateUser("user2", "hash2")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	secret, err := storage.CreateSecret(user1.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	// Попытка получить секрет user1 от имени user2
	_, err = storage.GetSecretByID(user2.ID, secret.ID)
	if err != ErrSecretNotFound {
		t.Errorf("GetSecretByID should return ErrSecretNotFound for wrong user: got %v", err)
	}
}

func TestGetUserSecrets(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	_, err = storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data1"), "meta1")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	_, err = storage.CreateSecret(user.ID, models.SecretTypeText, []byte("data2"), "meta2")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	secrets, err := storage.GetUserSecrets(user.ID)
	if err != nil {
		t.Fatalf("GetUserSecrets failed: %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("GetUserSecrets returned wrong count: got %d, want 2", len(secrets))
	}
}

func TestGetUserSecretsEmpty(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	secrets, err := storage.GetUserSecrets(user.ID)
	if err != nil {
		t.Fatalf("GetUserSecrets failed: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("GetUserSecrets returned wrong count: got %d, want 0", len(secrets))
	}
}

func TestUpdateSecret(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	secret, err := storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("olddata"), "oldmeta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	updatedSecret, err := storage.UpdateSecret(user.ID, secret.ID, []byte("newdata"), "newmeta")
	if err != nil {
		t.Fatalf("UpdateSecret failed: %v", err)
	}

	if string(updatedSecret.Data) != "newdata" {
		t.Errorf("UpdateSecret returned wrong data: got %s, want newdata", string(updatedSecret.Data))
	}

	if updatedSecret.Metadata != "newmeta" {
		t.Errorf("UpdateSecret returned wrong metadata: got %s, want newmeta", updatedSecret.Metadata)
	}

	if updatedSecret.Version != 2 {
		t.Errorf("UpdateSecret returned wrong version: got %d, want 2", updatedSecret.Version)
	}
}

func TestUpdateSecretNotFound(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	_, err = storage.UpdateSecret(user.ID, 999, []byte("data"), "meta")
	if err != ErrSecretNotFound {
		t.Errorf("UpdateSecret should return ErrSecretNotFound: got %v", err)
	}
}

func TestDeleteSecret(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	secret, err := storage.CreateSecret(user.ID, models.SecretTypeLoginPassword, []byte("data"), "meta")
	if err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}

	err = storage.DeleteSecret(user.ID, secret.ID)
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}

	secrets, err := storage.GetUserSecrets(user.ID)
	if err != nil {
		t.Fatalf("GetUserSecrets failed: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("DeleteSecret did not delete secret: got %d secrets, want 0", len(secrets))
	}
}

func TestDeleteSecretNotFound(t *testing.T) {
	storage := NewInMemoryStorage()

	user, err := storage.CreateUser("testuser", "hashedpassword")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	err = storage.DeleteSecret(user.ID, 999)
	if err != ErrSecretNotFound {
		t.Errorf("DeleteSecret should return ErrSecretNotFound: got %v", err)
	}
}
