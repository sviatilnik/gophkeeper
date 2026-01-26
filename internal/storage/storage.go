package storage

import (
	"errors"
	"sync"
	"time"

	"github.com/sviatilnik/gophkeeper/internal/models"
)

var (
	// ErrUserNotFound возвращается когда пользователь не найден в хранилище.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserExists возвращается когда пользователь с таким логином уже существует.
	ErrUserExists = errors.New("user already exists")
	// ErrSecretNotFound возвращается когда секрет не найден в хранилище.
	ErrSecretNotFound = errors.New("secret not found")
)

// Storage определяет интерфейс для хранения данных пользователей и секретов.
// Реализации этого интерфейса могут использовать различные хранилища:
// память, база данных, файловая система и т.д.
type Storage interface {
	// CreateUser создает нового пользователя с указанным логином и хешем пароля.
	// Возвращает созданного пользователя или ошибку, если пользователь уже существует.
	CreateUser(login, passwordHash string) (*models.User, error)
	// GetUserByLogin получает пользователя по логину.
	// Возвращает пользователя или ErrUserNotFound, если пользователь не найден.
	GetUserByLogin(login string) (*models.User, error)
	// GetUserByID получает пользователя по уникальному идентификатору.
	// Возвращает пользователя или ErrUserNotFound, если пользователь не найден.
	GetUserByID(id int64) (*models.User, error)

	// CreateSecret создает новый секрет для указанного пользователя.
	// Возвращает созданный секрет с присвоенным идентификатором и версией 1.
	CreateSecret(userID int64, secretType models.SecretType, data []byte, metadata string) (*models.Secret, error)
	// GetSecretByID получает секрет по идентификатору для указанного пользователя.
	// Возвращает секрет или ErrSecretNotFound, если секрет не найден или не принадлежит пользователю.
	GetSecretByID(userID, secretID int64) (*models.Secret, error)
	// GetUserSecrets получает все секреты указанного пользователя.
	// Возвращает слайс секретов (может быть пустым, если секретов нет).
	GetUserSecrets(userID int64) ([]*models.Secret, error)
	// UpdateSecret обновляет существующий секрет.
	// Увеличивает версию секрета на 1 при успешном обновлении.
	// Возвращает обновленный секрет или ErrSecretNotFound, если секрет не найден.
	UpdateSecret(userID, secretID int64, data []byte, metadata string) (*models.Secret, error)
	// DeleteSecret удаляет секрет для указанного пользователя.
	// Возвращает ErrSecretNotFound, если секрет не найден или не принадлежит пользователю.
	DeleteSecret(userID, secretID int64) error
}

// InMemoryStorage реализует хранилище данных в памяти.
// Используется для тестирования и разработки.
// Не подходит для production, так как данные теряются при перезапуске приложения.
type InMemoryStorage struct {
	mu          sync.RWMutex
	users       map[string]*models.User  // login -> user
	usersByID   map[int64]*models.User   // id -> user
	secrets     map[int64][]*models.Secret // userID -> secrets
	nextUserID  int64
	nextSecretID int64
}

// NewInMemoryStorage создает новое хранилище в памяти.
// Инициализирует все необходимые структуры данных и счетчики идентификаторов.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		users:       make(map[string]*models.User),
		usersByID:   make(map[int64]*models.User),
		secrets:     make(map[int64][]*models.Secret),
		nextUserID:  1,
		nextSecretID: 1,
	}
}

// CreateUser создает нового пользователя
func (s *InMemoryStorage) CreateUser(login, passwordHash string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[login]; exists {
		return nil, ErrUserExists
	}

	user := &models.User{
		ID:        s.nextUserID,
		Login:     login,
		Password:  passwordHash,
		CreatedAt: time.Now().Unix(),
	}

	s.users[login] = user
	s.usersByID[user.ID] = user
	s.nextUserID++

	return user, nil
}

// GetUserByLogin получает пользователя по логину
func (s *InMemoryStorage) GetUserByLogin(login string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[login]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetUserByID получает пользователя по ID
func (s *InMemoryStorage) GetUserByID(id int64) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.usersByID[id]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// CreateSecret создает новый секрет
func (s *InMemoryStorage) CreateSecret(userID int64, secretType models.SecretType, data []byte, metadata string) (*models.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	secret := &models.Secret{
		ID:        s.nextSecretID,
		UserID:    userID,
		Type:      secretType,
		Data:      data,
		Metadata:  metadata,
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}

	s.secrets[userID] = append(s.secrets[userID], secret)
	s.nextSecretID++

	return secret, nil
}

// GetSecretByID получает секрет по ID
func (s *InMemoryStorage) GetSecretByID(userID, secretID int64) (*models.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secrets, exists := s.secrets[userID]
	if !exists {
		return nil, ErrSecretNotFound
	}

	for _, secret := range secrets {
		if secret.ID == secretID {
			return secret, nil
		}
	}

	return nil, ErrSecretNotFound
}

// GetUserSecrets получает все секреты пользователя
func (s *InMemoryStorage) GetUserSecrets(userID int64) ([]*models.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secrets, exists := s.secrets[userID]
	if !exists {
		return []*models.Secret{}, nil
	}

	// Возвращаем копию слайса
	result := make([]*models.Secret, len(secrets))
	copy(result, secrets)
	return result, nil
}

// UpdateSecret обновляет существующий секрет
func (s *InMemoryStorage) UpdateSecret(userID, secretID int64, data []byte, metadata string) (*models.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	secrets, exists := s.secrets[userID]
	if !exists {
		return nil, ErrSecretNotFound
	}

	for _, secret := range secrets {
		if secret.ID == secretID {
			secret.Data = data
			secret.Metadata = metadata
			secret.UpdatedAt = time.Now()
			secret.Version++
			return secret, nil
		}
	}

	return nil, ErrSecretNotFound
}

// DeleteSecret удаляет секрет
func (s *InMemoryStorage) DeleteSecret(userID, secretID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	secrets, exists := s.secrets[userID]
	if !exists {
		return ErrSecretNotFound
	}

	for i, secret := range secrets {
		if secret.ID == secretID {
			s.secrets[userID] = append(secrets[:i], secrets[i+1:]...)
			return nil
		}
	}

	return ErrSecretNotFound
}
