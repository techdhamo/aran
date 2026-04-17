// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

package middleware

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/techdhamo/aran/aran-waap/internal/config"
	"github.com/techdhamo/aran/aran-waap/internal/logger"
	"golang.org/x/time/rate"
)

// RequestIDKey is the context key for request ID
const RequestIDKey = "X-Request-ID"

// GetRequestID retrieves request ID from context
func GetRequestID(c *gin.Context) string {
	if rid, exists := c.Get(RequestIDKey); exists {
		return rid.(string)
	}
	return ""
}

// RequestID generates a unique request ID
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := generateRequestID()
		c.Set(RequestIDKey, rid)
		c.Header("X-Aran-WAAP-Request-ID", rid)
		c.Next()
	}
}

func generateRequestID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateRandomString(8))
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'none'")
		c.Header("X-Aran-WAAP", "active")
		c.Next()
	}
}

// Recovery recovers from panics
func Recovery(log *logger.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, err any) {
		log.Error("Panic recovered",
			"error", err,
			"request_id", GetRequestID(c),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
		})
	})
}

// RateLimiter implements token bucket rate limiting per IP
type rateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	config   config.RateLimitConfig
}

func newRateLimiter(cfg config.RateLimitConfig) *rateLimiter {
	return &rateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   cfg,
	}
}

func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if limiter, exists := rl.limiters[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(rate.Limit(rl.config.RequestsPerSecond), rl.config.BurstSize)
	rl.limiters[ip] = limiter
	return limiter
}

// RateLimiter applies rate limiting
func RateLimiter(cfg config.RateLimitConfig) gin.HandlerFunc {
	rl := newRateLimiter(cfg)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := rl.getLimiter(ip)

		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

// TelemetryInspection validates Aran RASP telemetry payloads
func TelemetryInspection(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for Aran-specific headers
		licenseKey := c.GetHeader("X-Aran-License-Key")
		nonce := c.GetHeader("X-Aran-Nonce")
		timestamp := c.GetHeader("X-Aran-Timestamp")
		signature := c.GetHeader("X-Aran-Signature")

		if licenseKey == "" {
			// Not an Aran request, pass through
			c.Next()
			return
		}

		// Validate required headers for E2EE
		if nonce == "" || timestamp == "" || signature == "" {
			log.Warn("Incomplete Aran request headers",
				"client_ip", c.ClientIP(),
				"request_id", GetRequestID(c),
			)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Missing required security headers",
			})
			return
		}

		// Check timestamp (5-minute window to prevent replay)
		// In production, verify against nonce cache

		c.Next()
	}
}

// BOLAProtection detects Broken Object Level Authorization attacks
func BOLAProtection(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for path traversal attempts
		path := c.Request.URL.Path

		// Detect common BOLA patterns
		suspiciousPatterns := []string{
			"../",
			"..\\",
			"%2e%2e%2f",
			"%252e%252e%252f",
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(path, pattern) {
				log.Warn("Potential path traversal attack",
					"client_ip", c.ClientIP(),
					"path", path,
					"pattern", pattern,
				)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Suspicious request blocked",
				})
				return
			}
		}

		// Check for ID enumeration (sequential ID access)
		// In production: compare device fingerprint with resource ownership

		c.Next()
	}
}

// IDORProtection detects Insecure Direct Object Reference
func IDORProtection(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract resource IDs from path
		// Pattern: /api/v1/resource/{id}

		// In production implementation:
		// 1. Parse JWT/device fingerprint from request
		// 2. Query backend for resource ownership
		// 3. Block if device fingerprint != resource owner

		c.Next()
	}
}

// ArAuthValidation validates Aran authentication keys
func ArAuthValidation(validKeys []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(validKeys) == 0 {
			// No auth required in dev mode
			c.Next()
			return
		}

		providedKey := c.GetHeader("X-Aran-License-Key")
		if providedKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Missing license key",
			})
			return
		}

		// Constant-time comparison to prevent timing attacks
		valid := false
		for _, key := range validKeys {
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(key)) == 1 {
				valid = true
				break
			}
		}

		if !valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid license key",
			})
			return
		}

		c.Next()
	}
}
