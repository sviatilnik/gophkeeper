# GophKeeper

GophKeeper - это клиент-серверная система для безопасного хранения приватных данных (логинов, паролей, текстовых и бинарных данных, данных банковских карт).

## Возможности

- Регистрация и аутентификация пользователей
- Безопасное хранение различных типов данных:
  - Пары логин/пароль
  - Произвольные текстовые данные
  - Произвольные бинарные данные
  - Данные банковских карт
- Синхронизация данных между несколькими клиентами
- CLI интерфейс для работы с данными
- Шифрование данных с использованием AES-256-GCM
- Хеширование паролей с использованием bcrypt

## Архитектура

Проект состоит из следующих компонентов:

- **cmd/client** - CLI клиентское приложение
- **cmd/server** - HTTP сервер
- **internal/models** - модели данных (User, Secret, AuthToken и т.д.)
- **internal/storage** - интерфейс и реализация хранилища данных
- **internal/server** - HTTP обработчики и серверная логика
- **internal/client** - клиентская библиотека для взаимодействия с сервером
- **internal/auth** - управление токенами аутентификации
- **internal/crypto** - функции шифрования и хеширования

## Установка и запуск

### Сервер

```bash
cd cmd/server
go run server.go -addr :8080
```

Сервер поддерживает graceful shutdown:
- При получении сигнала SIGTERM или SIGINT сервер корректно завершает обработку текущих запросов
- По умолчанию таймаут graceful shutdown составляет 30 секунд (настраивается через флаг `-shutdown-timeout`)
- После завершения всех активных соединений сервер останавливается

Пример остановки сервера:
```bash
# Отправить сигнал завершения процессу
kill -SIGTERM <pid>
# или
kill -SIGINT <pid>
# или просто нажать Ctrl+C в терминале
```

### Клиент

```bash
cd cmd/client
go run client.go --server http://localhost:8080 [command]
```

Или после сборки:
```bash
./client --server http://localhost:8080 [command]
```

### Сборка клиента с информацией о версии

```bash
cd cmd/client
./build.sh 1.0.0
```

## Использование клиента

Клиент использует библиотеку Cobra для управления командами. Доступны следующие команды:

### Основные команды

- `gophkeeper register` - регистрация нового пользователя
- `gophkeeper login` - вход в систему
- `gophkeeper list` - список всех секретов
- `gophkeeper get <id>` - получить секрет по ID
- `gophkeeper add` - добавить новый секрет (интерактивно)
- `gophkeeper update <id>` - обновить секрет
- `gophkeeper delete <id>` - удалить секрет
- `gophkeeper sync` - синхронизировать данные с сервером
- `gophkeeper version` - показать информацию о версии
- `gophkeeper help` - показать справку по командам

### Флаги

- `--server, -s` - URL сервера GophKeeper (по умолчанию: `http://localhost:8080`)

### Примеры использования

```bash
# Регистрация нового пользователя
./client register

# Вход в систему
./client login

# Получить список всех секретов
./client list

# Получить секрет по ID
./client get 1

# Добавить новый секрет
./client add

# Обновить секрет
./client update 1

# Удалить секрет
./client delete 1

# Синхронизировать данные
./client sync

# Показать версию
./client version

# Использование с другим сервером
./client --server https://api.example.com list
```

## API эндпоинты

Полное описание API доступно в формате OpenAPI/Swagger: [api/swagger.yaml](api/swagger.yaml)

### Быстрая справка по эндпоинтам:

#### Регистрация
```
POST /api/register
Body: {"login": "user", "password": "pass"}
```

#### Вход
```
POST /api/login
Body: {"login": "user", "password": "pass"}
```

#### Получить все секреты
```
GET /api/secrets
Headers: Authorization: Bearer <token>
```

#### Создать секрет
```
POST /api/secrets
Headers: Authorization: Bearer <token>
Body: {"type": "login_password", "data": [...], "metadata": "..."}
```

#### Получить секрет по ID
```
GET /api/secrets/{id}
Headers: Authorization: Bearer <token>
```

#### Обновить секрет
```
PUT /api/secrets/{id}
Headers: Authorization: Bearer <token>
Body: {"data": [...], "metadata": "..."}
```

#### Удалить секрет
```
DELETE /api/secrets/{id}
Headers: Authorization: Bearer <token>
```

#### Синхронизация
```
GET /api/sync
Headers: Authorization: Bearer <token>
```

### Просмотр Swagger документации

Для просмотра интерактивной документации Swagger можно использовать:

1. **Swagger UI**: Загрузите `api/swagger.yaml` на https://editor.swagger.io/
2. **Redoc**: Используйте https://redocly.github.io/redoc/ для генерации документации
3. **Локально**: Используйте инструменты вроде `swagger-ui` или `redoc-cli`

Пример с redoc-cli:
```bash
npm install -g redoc-cli
redoc-cli serve api/swagger.yaml
```

## Тестирование

Запуск всех тестов:

```bash
go test ./internal/... -v
```

Проверка покрытия тестами:

```bash
go test ./internal/... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Безопасность

- Пароли хешируются с использованием bcrypt
- Данные шифруются с использованием AES-256-GCM
- Токены аутентификации для защиты API
- Постоянное по времени сравнение для предотвращения атак по времени

## Лицензия

MIT
