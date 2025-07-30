package jwtmanager

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Экспортируемые метрики
var (
	// Счётчики операций
	GenerateAccessTokenCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_access_tokens_total",
		Help: "Total number of generated access tokens",
	})
	GenerateRefreshTokenCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_refresh_tokens_total",
		Help: "Total number of generated refresh tokens",
	})
	ValidateTokenCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_validate_tokens_total",
		Help: "Total number of validated tokens",
	})
	RefreshAccessTokenCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_refresh_access_tokens_total",
		Help: "Total number of refreshed access tokens",
	})
	// Счётчики ошибок
	GenerateAccessTokenErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_access_token_errors_total",
		Help: "Total number of errors during access token generation",
	})
	GenerateRefreshTokenErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_generate_refresh_token_errors_total",
		Help: "Total number of errors during refresh token generation",
	})
	ValidateTokenErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_validate_token_errors_total",
		Help: "Total number of errors during token validation",
	})
	RefreshAccessTokenErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwtmanager_refresh_access_token_errors_total",
		Help: "Total number of errors during access token refresh",
	})
	// Гистограммы для latency
	GenerateAccessTokenDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "jwtmanager_generate_access_token_duration_seconds",
		Help:    "Latency of access token generation in seconds",
		Buckets: prometheus.DefBuckets,
	})
	ValidateTokenDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "jwtmanager_validate_token_duration_seconds",
		Help:    "Latency of token validation in seconds",
		Buckets: prometheus.DefBuckets,
	})
	RefreshAccessTokenDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "jwtmanager_refresh_access_token_duration_seconds",
		Help:    "Latency of access token refresh in seconds",
		Buckets: prometheus.DefBuckets,
	})
)
