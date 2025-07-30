package jwtmanager_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/norchah/jwtmanager"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

type mockStorage struct {
	tokens map[string]struct {
		userID    string
		deviceID  string
		expiresAt time.Time
	}
}

func (s *mockStorage) SaveRefreshToken(token, userID, deviceID string, expiresAt time.Time) error {
	s.tokens[token] = struct {
		userID    string
		deviceID  string
		expiresAt time.Time
	}{userID, deviceID, expiresAt}
	return nil
}

func (s *mockStorage) ValidateRefreshToken(token string) (string, string, error) {
	data, exists := s.tokens[token]
	if !exists || data.expiresAt.Before(time.Now()) {
		return "", "", jwtmanager.ErrInvalidToken
	}
	return data.userID, data.deviceID, nil
}

func (s *mockStorage) RevokeRefreshToken(token string) error {
	delete(s.tokens, token)
	return nil
}

func TestGenerateAccessToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.Issuer,
		},
		Roles: []string{"user"},
	}
	token, err := manager.GenerateAccessToken(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Check kid in token
	parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return config.PublicKeys["1"], nil
	})
	assert.Equal(t, "1", parsedToken.Header["kid"])
}

func TestValidateToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.Issuer,
		},
		Roles: []string{"user"},
	}
	token, err := manager.GenerateAccessToken(claims)
	assert.NoError(t, err)

	parsedClaims, err := manager.ValidateToken(token)
	assert.NoError(t, err)
	assert.Equal(t, claims.Subject, parsedClaims.Subject)
	assert.Equal(t, claims.Roles, parsedClaims.Roles)
}

func TestRefreshAccessToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	storage := &mockStorage{tokens: make(map[string]struct {
		userID    string
		deviceID  string
		expiresAt time.Time
	})}
	refreshToken, err := manager.GenerateRefreshToken("user123", "device1")
	assert.NoError(t, err)

	err = storage.SaveRefreshToken(refreshToken, "user123", "device1", time.Now().Add(config.RefreshTTL))
	assert.NoError(t, err)

	newToken, newClaims, err := manager.RefreshAccessToken(refreshToken, storage)
	assert.NoError(t, err)
	assert.NotEmpty(t, newToken)
	assert.Equal(t, "user123", newClaims.Subject)
	assert.Equal(t, "device1", newClaims.DeviceID)
}

func TestGenerateRefreshTokenHash(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	refreshToken, err := manager.GenerateRefreshToken("user123", "device1")
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// Verify that the token is a valid SHA-256 hex string (64 characters)
	assert.Equal(t, 64, len(refreshToken), "Refresh token should be a 64-character SHA-256 hex string")
}

func TestValidateExpiredToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Second * 1,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.Issuer,
		},
		Roles: []string{"user"},
	}
	token, err := manager.GenerateAccessToken(claims)
	assert.NoError(t, err)

	_, err = manager.ValidateToken(token)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
}

func TestValidateInvalidToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.Issuer,
		},
		Roles: []string{"user"},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1"
	invalidToken, err := token.SignedString(wrongKey)
	assert.NoError(t, err)

	_, err = manager.ValidateToken(invalidToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature is invalid")
}

func TestValidateWrongIssuer(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "wrong-issuer",
		},
		Roles: []string{"user"},
	}
	token, err := manager.GenerateAccessToken(claims)
	assert.NoError(t, err)

	_, err = manager.ValidateToken(token)
	assert.ErrorIs(t, err, jwtmanager.ErrInvalidIssuer)
}

func TestRefreshInvalidToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	storage := &mockStorage{tokens: make(map[string]struct {
		userID    string
		deviceID  string
		expiresAt time.Time
	})}
	_, _, err = manager.RefreshAccessToken("non-existent-token", storage)
	assert.ErrorIs(t, err, jwtmanager.ErrInvalidToken)
}

func TestNewJWTManagerInvalidConfig(t *testing.T) {
	// Test with invalid TTL
	config := &jwtmanager.Config{
		AccessTTL:    0,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{},
		PublicKeys:   map[string]*rsa.PublicKey{},
		CurrentKeyID: "1",
	}
	_, err := jwtmanager.NewJWTManager(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TTL")

	// Test with missing issuer
	config = &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "",
		PrivateKeys:  map[string]*rsa.PrivateKey{},
		PublicKeys:   map[string]*rsa.PublicKey{},
		CurrentKeyID: "1",
	}
	_, err = jwtmanager.NewJWTManager(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing issuer")

	// Test with missing keys
	config = &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{},
		PublicKeys:   map[string]*rsa.PublicKey{},
		CurrentKeyID: "1",
	}
	_, err = jwtmanager.NewJWTManager(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing keys")

	// Test with invalid CurrentKeyID
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config = &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "2",
	}
	_, err = jwtmanager.NewJWTManager(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid current key ID")
}

func TestGetJWKS(t *testing.T) {
	privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"key1": privateKey1, "key2": privateKey2},
		PublicKeys:   map[string]*rsa.PublicKey{"key1": &privateKey1.PublicKey, "key2": &privateKey2.PublicKey},
		CurrentKeyID: "key1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	jwksBytes, err := manager.GetJWKS()
	assert.NoError(t, err)

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	err = json.Unmarshal(jwksBytes, &jwks)
	assert.NoError(t, err)
	assert.Len(t, jwks.Keys, 2)
	assert.Equal(t, "RSA", jwks.Keys[0].Kty)
	assert.Contains(t, []string{"key1", "key2"}, jwks.Keys[0].Kid)
	assert.NotEmpty(t, jwks.Keys[0].N)
	assert.NotEmpty(t, jwks.Keys[0].E)
	assert.Equal(t, "RSA", jwks.Keys[1].Kty)
	assert.Contains(t, []string{"key1", "key2"}, jwks.Keys[1].Kid)
	assert.NotEmpty(t, jwks.Keys[1].N)
	assert.NotEmpty(t, jwks.Keys[1].E)
}

func TestValidateTokenWithRotatedKey(t *testing.T) {
	privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"key1": privateKey1, "key2": privateKey2},
		PublicKeys:   map[string]*rsa.PublicKey{"key1": &privateKey1.PublicKey, "key2": &privateKey2.PublicKey},
		CurrentKeyID: "key2",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	// Generate token with old key (key1)
	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.Issuer,
		},
		Roles: []string{"user"},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key1"
	validToken, err := token.SignedString(privateKey1)
	assert.NoError(t, err)

	// Validate token with old key
	parsedClaims, err := manager.ValidateToken(validToken)
	assert.NoError(t, err)
	assert.Equal(t, claims.Subject, parsedClaims.Subject)
	assert.Equal(t, claims.Roles, parsedClaims.Roles)

	// Try validating with missing kid
	token.Header["kid"] = "key3"
	invalidToken, err := token.SignedString(privateKey1)
	assert.NoError(t, err)
	_, err = manager.ValidateToken(invalidToken)
	assert.ErrorIs(t, err, jwtmanager.ErrInvalidKeyID)
}

func TestMetrics(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, err := jwtmanager.NewJWTManager(config)
	assert.NoError(t, err)

	// Reset metrics for test
	prometheus.DefaultRegisterer.Unregister(jwtmanager.GenerateAccessTokenCounter)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.ValidateTokenCounter)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.GenerateRefreshTokenCounter)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.RefreshAccessTokenCounter)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.GenerateAccessTokenErrors)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.GenerateRefreshTokenErrors)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.ValidateTokenErrors)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.RefreshAccessTokenErrors)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.GenerateAccessTokenDuration)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.ValidateTokenDuration)
	prometheus.DefaultRegisterer.Unregister(jwtmanager.RefreshAccessTokenDuration)
	// Re-register metrics
	jwtmanager.GenerateAccessTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_access_tokens_total",
		Help: "Total number of generated access tokens",
	})
	jwtmanager.ValidateTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_validate_tokens_total",
		Help: "Total number of validated tokens",
	})
	jwtmanager.GenerateRefreshTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_refresh_tokens_total",
		Help: "Total number of generated refresh tokens",
	})
	jwtmanager.RefreshAccessTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_refresh_access_tokens_total",
		Help: "Total number of refreshed access tokens",
	})
	jwtmanager.GenerateAccessTokenErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_access_token_errors_total",
		Help: "Total number of errors during access token generation",
	})
	jwtmanager.GenerateRefreshTokenErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_refresh_token_errors_total",
		Help: "Total number of errors during refresh token generation",
	})
	jwtmanager.ValidateTokenErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_validate_token_errors_total",
		Help: "Total number of errors during token validation",
	})
	jwtmanager.RefreshAccessTokenErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_refresh_access_token_errors_total",
		Help: "Total number of errors during access token refresh",
	})
	jwtmanager.GenerateAccessTokenDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "jwtmanager_generate_access_token_duration_seconds",
		Help:    "Latency of access token generation in seconds",
		Buckets: prometheus.DefBuckets,
	})
	jwtmanager.ValidateTokenDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "jwtmanager_validate_token_duration_seconds",
		Help:    "Latency of token validation in seconds",
		Buckets: prometheus.DefBuckets,
	})
	jwtmanager.RefreshAccessTokenDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "jwtmanager_refresh_access_token_duration_seconds",
		Help:    "Latency of access token refresh in seconds",
		Buckets: prometheus.DefBuckets,
	})

	// Generate access token
	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.Issuer,
		},
		Roles: []string{"user"},
	}
	token, err := manager.GenerateAccessToken(claims)
	assert.NoError(t, err)

	// Validate token
	_, err = manager.ValidateToken(token)
	assert.NoError(t, err)

	// Generate refresh token
	refreshToken, err := manager.GenerateRefreshToken("user123", "device1")
	assert.NoError(t, err)

	// Refresh access token
	storage := &mockStorage{tokens: make(map[string]struct {
		userID    string
		deviceID  string
		expiresAt time.Time
	})}
	err = storage.SaveRefreshToken(refreshToken, "user123", "device1", time.Now().Add(config.RefreshTTL))
	assert.NoError(t, err)
	_, _, err = manager.RefreshAccessToken(refreshToken, storage)
	assert.NoError(t, err)

	// Check counters
	assert.Equal(t, 2.0, testutil.ToFloat64(jwtmanager.GenerateAccessTokenCounter), "GenerateAccessTokenCounter should be 2")
	assert.Equal(t, 1.0, testutil.ToFloat64(jwtmanager.ValidateTokenCounter), "ValidateTokenCounter should be 1")
	assert.Equal(t, 1.0, testutil.ToFloat64(jwtmanager.GenerateRefreshTokenCounter), "GenerateRefreshTokenCounter should be 1")
	assert.Equal(t, 1.0, testutil.ToFloat64(jwtmanager.RefreshAccessTokenCounter), "RefreshAccessTokenCounter should be 1")
	assert.Equal(t, 0.0, testutil.ToFloat64(jwtmanager.GenerateAccessTokenErrors), "GenerateAccessTokenErrors should be 0")
	assert.Equal(t, 0.0, testutil.ToFloat64(jwtmanager.GenerateRefreshTokenErrors), "GenerateRefreshTokenErrors should be 0")
	assert.Equal(t, 0.0, testutil.ToFloat64(jwtmanager.ValidateTokenErrors), "ValidateTokenErrors should be 0")
	assert.Equal(t, 0.0, testutil.ToFloat64(jwtmanager.RefreshAccessTokenErrors), "RefreshAccessTokenErrors should be 0")

	// Check histograms using CollectAndCompare (only count, as sum varies)
	metrics := `
		# HELP jwtmanager_generate_access_token_duration_seconds Latency of access token generation in seconds
		# TYPE jwtmanager_generate_access_token_duration_seconds histogram
		jwtmanager_generate_access_token_duration_seconds_count 2
	`
	err = testutil.CollectAndCompare(jwtmanager.GenerateAccessTokenDuration, strings.NewReader(metrics), "jwtmanager_generate_access_token_duration_seconds_count")
	assert.NoError(t, err, "GenerateAccessTokenDuration should have 2 observations")

	metrics = `
		# HELP jwtmanager_validate_token_duration_seconds Latency of token validation in seconds
		# TYPE jwtmanager_validate_token_duration_seconds histogram
		jwtmanager_validate_token_duration_seconds_count 1
	`
	err = testutil.CollectAndCompare(jwtmanager.ValidateTokenDuration, strings.NewReader(metrics), "jwtmanager_validate_token_duration_seconds_count")
	assert.NoError(t, err, "ValidateTokenDuration should have 1 observation")

	metrics = `
		# HELP jwtmanager_refresh_access_token_duration_seconds Latency of access token refresh in seconds
		# TYPE jwtmanager_refresh_access_token_duration_seconds histogram
		jwtmanager_refresh_access_token_duration_seconds_count 2
	`
	err = testutil.CollectAndCompare(jwtmanager.RefreshAccessTokenDuration, strings.NewReader(metrics), "jwtmanager_refresh_access_token_duration_seconds_count")
	assert.NoError(t, err, "RefreshAccessTokenDuration should have 2 observations")
}

func BenchmarkGenerateAccessToken(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := &jwtmanager.Config{
		AccessTTL:    time.Minute * 15,
		RefreshTTL:   time.Hour * 24 * 7,
		Issuer:       "auth-service",
		PrivateKeys:  map[string]*rsa.PrivateKey{"1": privateKey},
		PublicKeys:   map[string]*rsa.PublicKey{"1": &privateKey.PublicKey},
		CurrentKeyID: "1",
	}
	manager, _ := jwtmanager.NewJWTManager(config)
	claims := jwtmanager.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    config.Issuer,
		},
		Roles: []string{"user"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.GenerateAccessToken(claims)
	}
}
