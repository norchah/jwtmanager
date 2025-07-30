```markdown
# jwtmanager

`jwtmanager` — это Go-модуль для работы с JSON Web Tokens (JWT) в микросервисной архитектуре. Он предназначен для централизованной аутентификации (SSO), генерации и валидации токенов, управления refresh-токенами и поддержки ротации ключей через JWKS. Модуль следует принципам zero-trust, least privilege и соответствует требованиям ФЗ-152/242 (без ПДн в токенах, локализация ключей в РФ).

## Основные возможности
- **Генерация токенов**: Access-токены (15 минут, RS256) и refresh-токены (7 дней, хэшируются SHA-256).
- **Валидация токенов**: Проверка подписи, issuer, expiration, `kid` (key ID).
- **Кастомные claims**: Поддержка `Roles` (RBAC), `MFAVerified` (MFA), `DeviceID` (сессии), `TenantID` (multi-tenant).
- **Ротация ключей**: Поддержка нескольких ключей через JWKS для zero-downtime обновлений.
- **Stateless-дизайн**: Токены валидируются без состояния, refresh-токены хранятся через интерфейс `Storage` (например, PostgreSQL/Redis).
- **Мониторинг**: Prometheus-метрики для операций и latency.
- **Тесты**: Покрытие >90%, включая happy path, edge cases и benchmarks.

## Установка
```bash
go get github.com/norchah/jwtmanager
```

Требования:
- Go 1.24.5 или выше.
- Зависимости:
  - `github.com/golang-jwt/jwt/v5`
  - `golang.org/x/crypto`
  - `github.com/prometheus/client_golang`

## Использование
Модуль предоставляет API для генерации, валидации и обновления токенов. Основной тип — `JWTManager`.

### Инициализация
```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"
	"github.com/norchah/jwtmanager"
)

func main() {
	// Генерация ключей (в продакшене загружать из безопасного хранилища)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// Конфигурация
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"key1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"key1": &privateKey.PublicKey},
		CurrentKeyID: "key1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	if err != nil {
		log.Fatalf("Ошибка инициализации: %v", err)
	}
}
```

### Генерация access-токена
```go
claims := jwtmanager.Claims{
	RegisteredClaims: jwt.RegisteredClaims{
		Subject:   "user123",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    config.Issuer,
	},
	Roles:       []string{"user"},
	DeviceID:    "device1",
	MFAVerified: true,
	TenantID:    "tenant1",
}
token, err := manager.GenerateAccessToken(claims)
if err != nil {
	log.Fatalf("Ошибка генерации токена: %v", err)
}
```

### Валидация токена
```go
parsedClaims, err := manager.ValidateToken(token)
if err != nil {
	log.Fatalf("Ошибка валидации: %v", err)
}
```

### Генерация refresh-токена
```go
refreshToken, err := manager.GenerateRefreshToken("user123", "device1")
if err != nil {
	log.Fatalf("Ошибка генерации refresh-токена: %v", err)
}
```

### Обновление access-токена
```go
newToken, newClaims, err := manager.RefreshAccessToken(refreshToken, storage)
if err != nil {
	log.Fatalf("Ошибка обновления: %v", err)
}
```

### Получение JWKS
```go
jwks, err := manager.GetJWKS()
if err != nil {
	log.Fatalf("Ошибка получения JWKS: %v", err)
}
```

## Мониторинг
Модуль экспортирует Prometheus-метрики для мониторинга операций и производительности:
- **Счётчики**:
  - `jwtmanager_generate_access_tokens_total`: Количество сгенерированных access-токенов.
  - `jwtmanager_generate_refresh_tokens_total`: Количество сгенерированных refresh-токенов.
  - `jwtmanager_validate_tokens_total`: Количество валидаций токенов.
  - `jwtmanager_refresh_access_tokens_total`: Количество обновлений access-токенов.
  - `jwtmanager_generate_access_token_errors_total`: Ошибки генерации access-токенов.
  - `jwtmanager_generate_refresh_token_errors_total`: Ошибки генерации refresh-токенов.
  - `jwtmanager_validate_token_errors_total`: Ошибки валидации токенов.
  - `jwtmanager_refresh_access_token_errors_total`: Ошибки обновления токенов.
- **Гистограммы**:
  - `jwtmanager_generate_access_token_duration_seconds`: Время генерации access-токенов.
  - `jwtmanager_validate_token_duration_seconds`: Время валидации токенов.
  - `jwtmanager_refresh_access_token_duration_seconds`: Время обновления токенов.

Для использования метрик настройте Prometheus endpoint:
```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

func main() {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9090", nil)
}
```

## Примеры
Смотрите `examples/main.go` для полного примера использования, включая генерацию ключей, токенов, валидацию и JWKS.

## Архитектурные решения
### Для разработчиков
- **Stateless-дизайн**: Модуль не хранит состояние, кроме refresh-токенов (через интерфейс `Storage`), что соответствует ТЗ (раздел 1).
- **Ротация ключей**: Поддержка нескольких ключей через `kid` в JWKS обеспечивает zero-downtime (раздел 3.3).
- **Безопасность**:
  - Используется RS256 для подписи (OWASP-рекомендация).
  - Refresh-токены хэшируются SHA-256 (раздел 4.4).
  - Проверка issuer и `kid` для zero-trust (раздел 6).
  - ПДн отсутствуют в токенах, что упрощает compliance с ФЗ-152.
- **Тесты**: Покрытие >90% (раздел 7), включая edge cases (невалидные/истёкшие токены, неверный issuer, отсутствующий `kid`).
- **Мониторинг**: Prometheus-метрики для операций и latency (раздел 7).
- **Расширяемость**:
  - Интерфейс `Storage` позволяет интегрировать PostgreSQL/Redis.
  - Кастомные claims (`Roles`, `MFAVerified`, `DeviceID`, `TenantID`) поддерживают RBAC и MFA (раздел 2.1).
- **Ограничения**:
  - OAuth 2.1 (redirect_uri) реализуется в auth-сервисе, а не в модуле.
  - Аудит в ELK реализуется в auth-сервисе.

### Для пользователей
- Модуль универсален для микросервисов: любой сервис может валидировать токены через JWKS.
- Простая интеграция с GIN (см. примеры в будущем `examples/middleware.go`).
- Поддержка ротации ключей позволяет обновлять ключи без остановки сервиса.
- Prometheus-метрики для мониторинга производительности.
- Минимальные зависимости: `golang-jwt/jwt/v5`, `golang.org/x/crypto`, `prometheus/client_golang`.

## Структура проекта
```
jwtmanager/
├── go.mod
├── go.sum
├── jwtmanager.go        // Основной API
├── types.go             // Структуры и ошибки
├── jwks.go              // Логика JWKS
├── metrics.go           // Prometheus-метрики
├── jwtmanager_test.go   // Тесты
├── README.md            // Документация
├── examples/
│   └── main.go          // Пример использования
```

## Тестирование
```bash
go test ./... -v -cover
```
Покрытие: >90%. Тесты включают:
- Генерацию и валидацию токенов.
- Обновление токенов.
- Проверку JWKS и ротации ключей.
- Edge cases (невалидные/истёкшие токены, неверный issuer/`kid`).
- Проверку Prometheus-метрик.

## Планы
- Добавить пример GIN-middleware в `examples/`.
- Настроить CI/CD через GitHub Actions (раздел 7 ТЗ).

## Лицензия
MIT (или proprietary для internal использования).
```