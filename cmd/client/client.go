package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/sviatilnik/gophkeeper/internal/client"
	"github.com/sviatilnik/gophkeeper/internal/models"
	"golang.org/x/term"
)

var (
	buildVersion string
	buildDate    string
	buildCommit  string

	// Глобальный клиент
	gophClient *client.Client
	serverURL  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper - безопасное хранилище приватных данных",
		Long: `GophKeeper - это клиент-серверная система для безопасного хранения
приватных данных (логинов, паролей, текстовых и бинарных данных, данных банковских карт).`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Инициализация клиента при выполнении любой команды
			gophClient = client.NewClient(serverURL)
		},
	}

	// Глобальный флаг для URL сервера
	rootCmd.PersistentFlags().StringVarP(&serverURL, "server", "s", "http://localhost:8080", "URL сервера GophKeeper")

	// Команда регистрации
	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Зарегистрировать нового пользователя",
		Long:  "Регистрирует нового пользователя в системе и автоматически выполняет вход",
		RunE:  runRegister,
	}
	rootCmd.AddCommand(registerCmd)

	// Команда входа
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Войти в систему",
		Long:  "Выполняет аутентификацию пользователя и сохраняет токен",
		RunE:  runLogin,
	}
	rootCmd.AddCommand(loginCmd)

	// Команда списка секретов
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "Показать список всех секретов",
		Long:  "Выводит список всех секретов текущего пользователя",
		RunE:  runList,
	}
	rootCmd.AddCommand(listCmd)

	// Команда получения секрета
	getCmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Получить секрет по ID",
		Long:  "Выводит детальную информацию о секрете по его идентификатору",
		Args:  cobra.ExactArgs(1),
		RunE:  runGet,
	}
	rootCmd.AddCommand(getCmd)

	// Команда добавления секрета
	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Добавить новый секрет",
		Long:  "Интерактивно создает новый секрет",
		RunE:  runAdd,
	}
	rootCmd.AddCommand(addCmd)

	// Команда обновления секрета
	updateCmd := &cobra.Command{
		Use:   "update [id]",
		Short: "Обновить существующий секрет",
		Long:  "Обновляет данные и метаинформацию секрета",
		Args:  cobra.ExactArgs(1),
		RunE:  runUpdate,
	}
	rootCmd.AddCommand(updateCmd)

	// Команда удаления секрета
	deleteCmd := &cobra.Command{
		Use:   "delete [id]",
		Short: "Удалить секрет",
		Long:  "Удаляет секрет по его идентификатору",
		Args:  cobra.ExactArgs(1),
		RunE:  runDelete,
	}
	rootCmd.AddCommand(deleteCmd)

	// Команда синхронизации
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Синхронизировать данные с сервером",
		Long:  "Получает все секреты пользователя с сервера для синхронизации",
		RunE:  runSync,
	}
	rootCmd.AddCommand(syncCmd)

	// Команда версии
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Показать информацию о версии",
		Long:  "Выводит версию, дату сборки и коммит",
		Run:   runVersion,
	}
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runRegister(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Login: ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	password, err := readPassword("Password: ")
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}

	resp, err := gophClient.Register(login, password)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	fmt.Printf("Successfully registered and logged in as %s\n", resp.User.Login)
	return nil
}

func runLogin(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Login: ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	password, err := readPassword("Password: ")
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}

	resp, err := gophClient.Login(login, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	fmt.Printf("Successfully logged in as %s\n", resp.User.Login)
	return nil
}

func runList(cmd *cobra.Command, args []string) error {
	secrets, err := gophClient.GetSecrets()
	if err != nil {
		return fmt.Errorf("failed to get secrets: %w", err)
	}

	if len(secrets) == 0 {
		fmt.Println("No secrets found")
		return nil
	}

	fmt.Println("Secrets:")
	for _, secret := range secrets {
		fmt.Printf("  ID: %d, Type: %s, Metadata: %s, Version: %d\n",
			secret.ID, secret.Type, secret.Metadata, secret.Version)
	}
	return nil
}

func runGet(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	secret, err := gophClient.GetSecret(id)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	fmt.Printf("Secret ID: %d\n", secret.ID)
	fmt.Printf("Type: %s\n", secret.Type)
	fmt.Printf("Metadata: %s\n", secret.Metadata)
	fmt.Printf("Data (base64): %s\n", base64.StdEncoding.EncodeToString(secret.Data))
	fmt.Printf("Version: %d\n", secret.Version)
	return nil
}

func runAdd(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Secret types: login_password, text, binary, card")
	fmt.Print("Type: ")
	typeStr, _ := reader.ReadString('\n')
	typeStr = strings.TrimSpace(typeStr)

	secretType := models.SecretType(typeStr)
	if secretType != models.SecretTypeLoginPassword &&
		secretType != models.SecretTypeText &&
		secretType != models.SecretTypeBinary &&
		secretType != models.SecretTypeCard {
		return fmt.Errorf("invalid secret type: %s", typeStr)
	}

	fmt.Print("Data (will be base64 encoded): ")
	dataStr, _ := reader.ReadString('\n')
	dataStr = strings.TrimSpace(dataStr)
	data := []byte(dataStr)

	fmt.Print("Metadata: ")
	metadata, _ := reader.ReadString('\n')
	metadata = strings.TrimSpace(metadata)

	secret, err := gophClient.CreateSecret(secretType, data, metadata)
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	fmt.Printf("Secret created with ID: %d\n", secret.ID)
	return nil
}

func runUpdate(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Data (will be base64 encoded): ")
	dataStr, _ := reader.ReadString('\n')
	dataStr = strings.TrimSpace(dataStr)
	data := []byte(dataStr)

	fmt.Print("Metadata: ")
	metadata, _ := reader.ReadString('\n')
	metadata = strings.TrimSpace(metadata)

	secret, err := gophClient.UpdateSecret(id, data, metadata)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	fmt.Printf("Secret updated. New version: %d\n", secret.Version)
	return nil
}

func runDelete(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	err = gophClient.DeleteSecret(id)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Println("Secret deleted")
	return nil
}

func runSync(cmd *cobra.Command, args []string) error {
	secrets, err := gophClient.Sync()
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	fmt.Printf("Synced %d secrets\n", len(secrets))
	return nil
}

func runVersion(cmd *cobra.Command, args []string) {
	version := buildVersion
	if version == "" {
		version = "N/A"
	}

	date := buildDate
	if date == "" {
		date = "N/A"
	}

	commit := buildCommit
	if commit == "" {
		commit = "N/A"
	}

	fmt.Printf("version: %s\n", version)
	fmt.Printf("date: %s\n", date)
	fmt.Printf("commit: %s\n", commit)
}

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}
