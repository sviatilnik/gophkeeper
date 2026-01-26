# GophKeeper API Documentation

Этот каталог содержит описание протокола взаимодействия клиента и сервера GophKeeper.

## Файлы

- `swagger.yaml` - OpenAPI 3.0 спецификация API в формате YAML

## Описание протокола

GophKeeper использует REST API для взаимодействия между клиентом и сервером. Все запросы и ответы передаются в формате JSON.

### Аутентификация

Для доступа к защищенным эндпоинтам требуется токен аутентификации, который получается при регистрации или входе в систему. Токен передается в заголовке `Authorization` в формате:

```
Authorization: Bearer <token>
```

### Типы данных

API поддерживает следующие типы секретных данных:

- `login_password` - пара логин/пароль для веб-сайтов и приложений
- `text` - произвольные текстовые данные (заметки, коды и т.д.)
- `binary` - произвольные бинарные данные (файлы, изображения и т.д.)
- `card` - данные банковской карты

### Шифрование

Все секретные данные должны быть зашифрованы на клиенте перед отправкой на сервер. Данные передаются в формате base64. Сервер хранит данные в зашифрованном виде и не имеет доступа к расшифрованным данным.

### Версионирование

Каждый секрет имеет поле `version`, которое увеличивается при каждом обновлении. Это позволяет синхронизировать данные между несколькими клиентами и разрешать конфликты.

### Коды ответов

- `200 OK` - успешный запрос
- `201 Created` - ресурс успешно создан
- `204 No Content` - ресурс успешно удален
- `400 Bad Request` - неверный формат запроса
- `401 Unauthorized` - требуется аутентификация или токен невалиден
- `404 Not Found` - ресурс не найден
- `409 Conflict` - конфликт (например, пользователь уже существует)
- `500 Internal Server Error` - внутренняя ошибка сервера

## Просмотр документации

### Онлайн

1. Откройте https://editor.swagger.io/
2. Загрузите файл `swagger.yaml`
3. Просматривайте интерактивную документацию

### Локально с Redoc

```bash
npm install -g redoc-cli
redoc-cli serve swagger.yaml
```

### Локально с Swagger UI

```bash
docker run -p 8080:8080 -e SWAGGER_JSON=/swagger.yaml -v $(pwd):/swagger swaggerapi/swagger-ui
```

Затем откройте http://localhost:8080 в браузере.

## Примеры использования

### Регистрация и получение токена

```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"login": "user123", "password": "securePassword"}'
```

Ответ:
```json
{
  "token": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": 0
  },
  "user": {
    "id": 1,
    "login": "user123",
    "created_at": 1640995200
  }
}
```

### Создание секрета

```bash
curl -X POST http://localhost:8080/api/secrets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "type": "login_password",
    "data": "base64encodedencrypteddata",
    "metadata": "GitHub account"
  }'
```

### Получение всех секретов

```bash
curl -X GET http://localhost:8080/api/secrets \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```
