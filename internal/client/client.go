package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/sviatilnik/gophkeeper/internal/models"
)

// Client представляет клиент для взаимодействия с сервером GophKeeper
type Client struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewClient создает новый клиент
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

// SetToken устанавливает токен аутентификации
func (c *Client) SetToken(token string) {
	c.token = token
}

// Register регистрирует нового пользователя
func (c *Client) Register(login, password string) (*models.AuthResponse, error) {
	creds := models.UserCredentials{
		Login:    login,
		Password: password,
	}

	body, err := json.Marshal(creds)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/register", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed: %s", string(bodyBytes))
	}

	var authResp models.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	c.SetToken(authResp.Token.Token)
	return &authResp, nil
}

// Login выполняет вход пользователя в систему.
// После успешного входа автоматически устанавливает токен аутентификации.
// Возвращает ответ с токеном и информацией о пользователе или ошибку.
func (c *Client) Login(login, password string) (*models.AuthResponse, error) {
	creds := models.UserCredentials{
		Login:    login,
		Password: password,
	}

	body, err := json.Marshal(creds)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/login", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed: %s", string(bodyBytes))
	}

	var authResp models.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	c.SetToken(authResp.Token.Token)
	return &authResp, nil
}

// GetSecrets получает все секреты текущего пользователя с сервера.
// Требует установленный токен аутентификации.
// Возвращает слайс секретов или ошибку.
func (c *Client) GetSecrets() ([]*models.Secret, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/secrets", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get secrets: %s", string(bodyBytes))
	}

	var secrets []*models.Secret
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, err
	}

	return secrets, nil
}

// CreateSecret создает новый секрет на сервере.
// Требует установленный токен аутентификации.
// Возвращает созданный секрет с присвоенным идентификатором или ошибку.
func (c *Client) CreateSecret(secretType models.SecretType, data []byte, metadata string) (*models.Secret, error) {
	reqBody := map[string]interface{}{
		"type":     secretType,
		"data":     data,
		"metadata": metadata,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/secrets", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create secret: %s", string(bodyBytes))
	}

	var secret models.Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// GetSecret получает секрет по идентификатору с сервера.
// Требует установленный токен аутентификации.
// Возвращает секрет или ошибку, если секрет не найден.
func (c *Client) GetSecret(secretID int64) (*models.Secret, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/secrets/"+strconv.FormatInt(secretID, 10), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get secret: %s", string(bodyBytes))
	}

	var secret models.Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// UpdateSecret обновляет существующий секрет на сервере.
// Требует установленный токен аутентификации.
// Увеличивает версию секрета при успешном обновлении.
// Возвращает обновленный секрет или ошибку.
func (c *Client) UpdateSecret(secretID int64, data []byte, metadata string) (*models.Secret, error) {
	reqBody := map[string]interface{}{
		"data":     data,
		"metadata": metadata,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", c.baseURL+"/api/secrets/"+strconv.FormatInt(secretID, 10), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to update secret: %s", string(bodyBytes))
	}

	var secret models.Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// DeleteSecret удаляет секрет с сервера.
// Требует установленный токен аутентификации.
// Возвращает ошибку, если секрет не найден или удаление не удалось.
func (c *Client) DeleteSecret(secretID int64) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/api/secrets/"+strconv.FormatInt(secretID, 10), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete secret: %s", string(bodyBytes))
	}

	return nil
}

// Sync синхронизирует данные с сервером, получая все секреты пользователя.
// Требует установленный токен аутентификации.
// Возвращает слайс всех секретов пользователя или ошибку.
func (c *Client) Sync() ([]*models.Secret, error) {
	return c.GetSecrets()
}
