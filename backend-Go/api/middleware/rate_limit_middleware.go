// Package middleware provides Gin middleware for request context setup, security guards, and request validation.
// Request rate limiting is kept small and local so sensitive endpoints can fail closed
// without adding infrastructure dependencies.
package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
)

const defaultRateLimitWindow = time.Minute

// RateLimitRule describes a fixed-window rate limit.
type RateLimitRule struct {
	Name   string
	Limit  int
	Window time.Duration
}

type fixedWindowRateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	rule    RateLimitRule
	entries map[string]rateLimitEntry
}

type rateLimitEntry struct {
	windowStart time.Time
	requests    int
}

// AuthRateLimit throttles public authentication endpoints.
func AuthRateLimit() gin.HandlerFunc {
	return newRateLimitMiddleware(RateLimitRule{
		Name:   "auth",
		Limit:  10,
		Window: defaultRateLimitWindow,
	})
}

// NVDLookupRateLimit throttles NVD lookup requests.
func NVDLookupRateLimit() gin.HandlerFunc {
	return newRateLimitMiddleware(RateLimitRule{
		Name:   "nvd_lookup",
		Limit:  10,
		Window: defaultRateLimitWindow,
	})
}

// AIRateLimit throttles AI-assisted ingestion and ranking requests.
func AIRateLimit() gin.HandlerFunc {
	return newRateLimitMiddleware(RateLimitRule{
		Name:   "ai_ingestion",
		Limit:  5,
		Window: defaultRateLimitWindow,
	})
}

func newRateLimitMiddleware(rule RateLimitRule) gin.HandlerFunc {
	limiter := newFixedWindowRateLimiter(rule, time.Now)

	return func(ctx *gin.Context) {
		key := ctx.ClientIP()
		allowed, retryAfter := limiter.Allow(key)
		if allowed {
			ctx.Next()
			return
		}

		ec := appcontext.FromGinContext(ctx)
		ec.Logger().Warn("rate limit exceeded",
			"rule", rule.Name,
			"method", ctx.Request.Method,
			"path", ctx.Request.URL.Path,
			"source_ip", key,
			"retry_after_seconds", int64(retryAfter.Seconds()),
		)

		if retryAfter > 0 {
			ctx.Header("Retry-After", fmt.Sprintf("%d", int64(retryAfter.Seconds())))
		}

		ctx.AbortWithStatusJSON(http.StatusTooManyRequests, dto.ErrorResponse{
			Code:      "RATE_LIMITED",
			Message:   "Rate limit exceeded.",
			RequestID: ec.TransactionID(),
		})
	}
}

func newFixedWindowRateLimiter(rule RateLimitRule, now func() time.Time) *fixedWindowRateLimiter {
	if rule.Window <= 0 {
		rule.Window = defaultRateLimitWindow
	}
	if rule.Limit <= 0 {
		rule.Limit = 1
	}
	if now == nil {
		now = time.Now
	}

	return &fixedWindowRateLimiter{
		now:     now,
		rule:    rule,
		entries: make(map[string]rateLimitEntry),
	}
}

// Allow records a request for the supplied key and reports whether it is allowed.
func (l *fixedWindowRateLimiter) Allow(key string) (bool, time.Duration) {
	if key == "" {
		key = "unknown"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry, exists := l.entries[key]
	if !exists || now.Sub(entry.windowStart) >= l.rule.Window {
		l.entries[key] = rateLimitEntry{windowStart: now, requests: 1}
		return true, 0
	}

	if entry.requests < l.rule.Limit {
		entry.requests++
		l.entries[key] = entry
		return true, 0
	}

	retryAfter := l.rule.Window - now.Sub(entry.windowStart)
	if retryAfter < 0 {
		retryAfter = 0
	}

	l.entries[key] = entry
	return false, retryAfter
}
