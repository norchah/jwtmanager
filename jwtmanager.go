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
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.config.CurrentKeyID
	return token.SignedString(m.config.PrivateKeys[m.config.CurrentKeyID])
}

// GenerateRefreshToken creates a new refresh token.
func (m *JWTManager) GenerateRefreshToken(userID, deviceID string) (string, error) {
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
		return "", err
	}
	// Hash refresh token with SHA-256 for storage
	hash := sha256.Sum256([]byte(token))
	hashedToken := hex.EncodeToString(hash[:])
	return hashedToken, nil
}

// ValidateToken validates a JWT and returns its claims.
func (m *JWTManager) ValidateToken(tokenString string) (Claims, error) {
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
		return Claims{}, err
	}
	if !token.Valid {
		return Claims{}, ErrInvalidToken
	}
	if claims.Issuer != m.config.Issuer {
		return Claims{}, ErrInvalidIssuer
	}
	return claims, nil
}

// RefreshAccessToken generates a new access token using a refresh token.
func (m *JWTManager) RefreshAccessToken(refreshToken string, storage Storage) (string, Claims, error) {
	// Validate refresh token in storage
	userID, deviceID, err := storage.ValidateRefreshToken(refreshToken)
	if err != nil {
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
		return "", Claims{}, err
	}
	return newToken, claims, nil
}
