package jwtmanager

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager handles JWT generation, validation, and refresh.
type JWTManager struct {
	config *Config
}

// NewJWTManager creates a new JWTManager instance.
func NewJWTManager(config *Config) (*JWTManager, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &JWTManager{config: config}, nil
}

// GenerateAccessToken creates a new access token with the provided claims.
func (m *JWTManager) GenerateAccessToken(claims Claims) (string, error) {
	start := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.config.CurrentKeyID
	signedToken, err := token.SignedString(m.config.PrivateKeys[m.config.CurrentKeyID])
	if err != nil {
		GenerateAccessTokenErrors.Inc()
		return "", err
	}
	GenerateAccessTokenCounter.Inc()
	GenerateAccessTokenDuration.Observe(time.Since(start).Seconds())
	return signedToken, nil
}

// GenerateRefreshToken creates a new refresh token.
func (m *JWTManager) GenerateRefreshToken(userID, deviceID string) (string, error) {
	start := time.Now()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":    userID,
		"device": deviceID,
		"exp":    time.Now().Add(m.config.RefreshTTL).Unix(),
		"iat":    time.Now().Unix(),
		"iss":    m.config.Issuer,
	})
	refreshToken.Header["kid"] = m.config.CurrentKeyID
	token, err := refreshToken.SignedString(m.config.PrivateKeys[m.config.CurrentKeyID])
	if err != nil {
		GenerateRefreshTokenErrors.Inc()
		return "", err
	}
	// Hash refresh token with SHA-256 for storage
	hash := sha256.Sum256([]byte(token))
	hashedToken := hex.EncodeToString(hash[:])
	GenerateRefreshTokenCounter.Inc()
	RefreshAccessTokenDuration.Observe(time.Since(start).Seconds())
	return hashedToken, nil
}

// ValidateToken validates a JWT and returns its claims.
func (m *JWTManager) ValidateToken(tokenString string) (Claims, error) {
	start := time.Now()
	claims := Claims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, ErrInvalidKeyID
		}
		publicKey, exists := m.config.PublicKeys[kid]
		if !exists {
			return nil, ErrInvalidKeyID
		}
		return publicKey, nil
	})
	if err != nil {
		ValidateTokenErrors.Inc()
		ValidateTokenDuration.Observe(time.Since(start).Seconds())
		return Claims{}, err
	}
	if !token.Valid {
		ValidateTokenErrors.Inc()
		ValidateTokenDuration.Observe(time.Since(start).Seconds())
		return Claims{}, ErrInvalidToken
	}
	if claims.Issuer != m.config.Issuer {
		ValidateTokenErrors.Inc()
		ValidateTokenDuration.Observe(time.Since(start).Seconds())
		return Claims{}, ErrInvalidIssuer
	}
	ValidateTokenCounter.Inc()
	ValidateTokenDuration.Observe(time.Since(start).Seconds())
	return claims, nil
}

// RefreshAccessToken generates a new access token using a refresh token.
func (m *JWTManager) RefreshAccessToken(refreshToken string, storage Storage) (string, Claims, error) {
	start := time.Now()
	// Validate refresh token in storage
	userID, deviceID, err := storage.ValidateRefreshToken(refreshToken)
	if err != nil {
		RefreshAccessTokenErrors.Inc()
		RefreshAccessTokenDuration.Observe(time.Since(start).Seconds())
		return "", Claims{}, err
	}
	// Generate new access token with device_id in claims
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    m.config.Issuer,
		},
		Roles:    []string{"user"}, // Default role, customizable
		DeviceID: deviceID,         // Include device_id for session tracking
	}
	newToken, err := m.GenerateAccessToken(claims)
	if err != nil {
		RefreshAccessTokenErrors.Inc()
		RefreshAccessTokenDuration.Observe(time.Since(start).Seconds())
		return "", Claims{}, err
	}
	RefreshAccessTokenCounter.Inc()
	RefreshAccessTokenDuration.Observe(time.Since(start).Seconds())
	return newToken, claims, nil
}
