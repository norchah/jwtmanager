package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/norchah/jwtmanager"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Запуск Prometheus метрик
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(":9090", nil))
	}()

	// Генерация ключей (в продакшене загружать из Yandex Cloud Secrets)
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Ошибка генерации ключа 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Ошибка генерации ключа 2: %v", err)
	}

	// Инициализация JWTManager
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"key1": privateKey1, "key2": privateKey2},
		PublicKeys:   map[string]*rsa.PublicKey{"key1": &privateKey1.PublicKey, "key2": &privateKey2.PublicKey},
		CurrentKeyID: "key2",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	if err != nil {
		log.Fatalf("Ошибка инициализации JWTManager: %v", err)
	}

	// Генерация access-токена
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
		log.Fatalf("Ошибка генерации access-токена: %v", err)
	}
	fmt.Printf("Access Token: %s\n", token)

	// Валидация токена
	parsedClaims, err := manager.ValidateToken(token)
	if err != nil {
		log.Fatalf("Ошибка валидации токена: %v", err)
	}
	fmt.Printf("Validated Claims: %+v\n", parsedClaims)

	// Генерация refresh-токена
	refreshToken, err := manager.GenerateRefreshToken("user123", "device1")
	if err != nil {
		log.Fatalf("Ошибка генерации refresh-токена: %v", err)
	}
	fmt.Printf("Refresh Token: %s\n", refreshToken)

	// Получение JWKS
	jwks, err := manager.GetJWKS()
	if err != nil {
		log.Fatalf("Ошибка получения JWKS: %v", err)
	}
	fmt.Printf("JWKS: %s\n", string(jwks))

	// Метрики доступны по http://localhost:9090/metrics
	fmt.Println("Метрики доступны по http://localhost:9090/metrics")
	select {} // Чтобы сервер не завершался
}
