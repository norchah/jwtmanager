package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/norchah/jwtmanager"
)

func main() {
	// Generate two RSA key pairs (in production, load from secure storage)
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key 1: %v", err)
	}
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key 2: %v", err)
	}

	// Initialize JWTManager with multiple keys
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
		log.Fatalf("Failed to initialize JWTManager: %v", err)
	}

	// Generate access token with current key
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
	}
	token, err := manager.GenerateAccessToken(claims)
	if err != nil {
		log.Fatalf("Failed to generate access token: %v", err)
	}
	fmt.Printf("Access Token: %s\n", token)

	// Validate token
	parsedClaims, err := manager.ValidateToken(token)
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}
	fmt.Printf("Validated Claims: %+v\n", parsedClaims)

	// Generate refresh token
	refreshToken, err := manager.GenerateRefreshToken("user123", "device1")
	if err != nil {
		log.Fatalf("Failed to generate refresh token: %v", err)
	}
	fmt.Printf("Refresh Token: %s\n", refreshToken)

	// Get JWKS
	jwks, err := manager.GetJWKS()
	if err != nil {
		log.Fatalf("Failed to get JWKS: %v", err)
	}
	fmt.Printf("JWKS: %s\n", string(jwks))
}
