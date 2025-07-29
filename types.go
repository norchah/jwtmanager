package jwtmanager

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds JWTManager configuration.
type Config struct {
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	Issuer       string
	Audience     string
	PrivateKeys  map[string]*rsa.PrivateKey // Map of key ID to private key
	PublicKeys   map[string]*rsa.PublicKey  // Map of key ID to public key
	CurrentKeyID string                     // Current key ID for signing
	JWKSURL      string
}

// Claims extends jwt.RegisteredClaims with custom fields.
type Claims struct {
	jwt.RegisteredClaims
	Roles       []string `json:"roles"`
	TenantID    string   `json:"tenant_id,omitempty"`
	MFAVerified bool     `json:"mfa_verified"`
	DeviceID    string   `json:"device_id,omitempty"`
}

// Storage defines the interface for refresh token storage.
type Storage interface {
	SaveRefreshToken(token, userID, deviceID string, expiresAt time.Time) error
	ValidateRefreshToken(token string) (userID, deviceID string, err error)
	RevokeRefreshToken(token string) error
}

// Errors
var (
	ErrInvalidToken  = errors.New("invalid token")
	ErrExpiredToken  = errors.New("token has expired")
	ErrInvalidIssuer = errors.New("invalid issuer")
	ErrInvalidKeyID  = errors.New("invalid or missing key ID")
)

// validate checks Config for required fields.
func (c *Config) validate() error {
	if c.AccessTTL <= 0 || c.RefreshTTL <= 0 {
		return errors.New("invalid TTL")
	}
	if c.Issuer == "" {
		return errors.New("missing issuer")
	}
	if len(c.PrivateKeys) == 0 || len(c.PublicKeys) == 0 {
		return errors.New("missing keys")
	}
	if c.CurrentKeyID == "" || c.PrivateKeys[c.CurrentKeyID] == nil || c.PublicKeys[c.CurrentKeyID] == nil {
		return errors.New("invalid current key ID")
	}
	return nil
}
