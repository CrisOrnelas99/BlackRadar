// Package ratelimit provides request rate-limiting middleware.
package ratelimit

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	requestcontext "blackradar/api/context"
	"blackradar/api/controller/dto"
)

const (
	defaultRateLimitWindow    = time.Minute
	defaultEntryRetention     = 10 * time.Minute
	defaultCleanupInterval    = time.Minute
	defaultUnknownClientKey   = "unknown"
	normalizedLoginContextKey = "normalized_login"
)

// RateLimitRule describes a fixed-window rate limit.
type RateLimitRule struct {
	Name   string
	Limit  int
	Window time.Duration
}

// KeyFunc returns the identity used for rate limiting.
//
// The returned value must not contain secrets or raw credentials.
type KeyFunc func(*gin.Context) string

// Config configures fixed-window rate-limit middleware.
type Config struct {
	Rule            RateLimitRule
	Key             KeyFunc
	CleanupInterval time.Duration
	EntryRetention  time.Duration
}

// Result describes the outcome of a rate-limit check.
type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	ResetAt    time.Time
}

type fixedWindowRateLimiter struct {
	mu              sync.Mutex
	now             func() time.Time
	rule            RateLimitRule
	entryRetention  time.Duration
	cleanupInterval time.Duration
	lastCleanupAt   time.Time
	entries         map[string]rateLimitEntry
}

type rateLimitEntry struct {
	windowStart time.Time
	lastSeenAt  time.Time
	requests    int
}

// New creates fixed-window rate-limit middleware.
//
// This implementation is process-local. Use a shared store such as Redis for
// multi-instance production deployments that require global enforcement.
func New(cfg Config) (gin.HandlerFunc, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	keyFunc := cfg.Key
	if keyFunc == nil {
		keyFunc = ClientIPKey
	}

	limiter := newFixedWindowRateLimiter(cfg.Rule, cfg.EntryRetention, cfg.CleanupInterval, time.Now)

	return func(ctx *gin.Context) {
		key := strings.TrimSpace(keyFunc(ctx))
		if key == "" {
			key = defaultUnknownClientKey
		}

		result := limiter.Allow(key)
		setRateLimitHeaders(ctx, result)
		if result.Allowed {
			ctx.Next()
			return
		}

		requestID := ""
		logger := slog.Default()
		if ec, err := requestcontext.FromGinContext(ctx); err == nil {
			logger = ec.Logger()
			requestID = ec.TransactionID()
		}

		logger.Warn(
			"rate limit exceeded",
			slog.String("rule", cfg.Rule.Name),
			slog.String("method", ctx.Request.Method),
			slog.String("path", ctx.Request.URL.Path),
			slog.Int64("retry_after_seconds", retryAfterSeconds(result.RetryAfter)),
		)

		ctx.AbortWithStatusJSON(http.StatusTooManyRequests, dto.ErrorResponse{
			Code:      "RATE_LIMITED",
			Message:   ErrRateLimited.Error(),
			RequestID: requestID,
		})
	}, nil
}

// AuthRateLimit throttles public authentication endpoints.
func AuthRateLimit() gin.HandlerFunc {
	return mustNew(Config{
		Rule: RateLimitRule{
			Name:   "auth",
			Limit:  10,
			Window: defaultRateLimitWindow,
		},
		Key: ClientIPKey,
	})
}

// NVDLookupRateLimit throttles NVD lookup requests.
func NVDLookupRateLimit() gin.HandlerFunc {
	return mustNew(Config{
		Rule: RateLimitRule{
			Name:   "nvd_lookup",
			Limit:  10,
			Window: defaultRateLimitWindow,
		},
		Key: PrincipalOrganizationKey,
	})
}

// AIRateLimit throttles AI-assisted ingestion and ranking requests.
func AIRateLimit() gin.HandlerFunc {
	return mustNew(Config{
		Rule: RateLimitRule{
			Name:   "ai_ingestion",
			Limit:  5,
			Window: defaultRateLimitWindow,
		},
		Key: PrincipalOrganizationKey,
	})
}

// ClientIPKey limits requests by Gin's resolved client IP.
//
// This is secure only when Gin's trusted proxy configuration is restricted to
// proxies controlled by the application operator.
func ClientIPKey(ctx *gin.Context) string {
	return ctx.ClientIP()
}

// PrincipalOrganizationKey limits authenticated requests by organization ID.
func PrincipalOrganizationKey(ctx *gin.Context) string {
	ec, err := requestcontext.FromGinContext(ctx)
	if err != nil {
		return ClientIPKey(ctx)
	}

	principal, err := ec.Principal()
	if err != nil || strings.TrimSpace(principal.OrganizationID) == "" {
		return ClientIPKey(ctx)
	}

	return "organization:" + principal.OrganizationID
}

// AuthAccountKey combines source IP with a normalized login identifier.
//
// The endpoint must store the normalized login identifier in Gin context only
// after parsing a size-limited request body. Do not include passwords or other
// secrets in this key.
func AuthAccountKey(ctx *gin.Context) string {
	clientIP := ClientIPKey(ctx)

	loginValue, exists := ctx.Get(normalizedLoginContextKey)
	if !exists {
		return clientIP
	}

	login, ok := loginValue.(string)
	if !ok || strings.TrimSpace(login) == "" {
		return clientIP
	}

	return clientIP + ":" + strings.ToLower(strings.TrimSpace(login))
}

// validateConfig rejects invalid rate-limit configuration.
func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Rule.Name) == "" {
		return ErrRateLimitNameRequired
	}
	if cfg.Rule.Limit <= 0 {
		return fmt.Errorf("%w: %q", ErrInvalidRateLimit, cfg.Rule.Name)
	}
	if cfg.Rule.Window <= 0 {
		return fmt.Errorf("%w: %q", ErrInvalidRateLimitWindow, cfg.Rule.Name)
	}
	if cfg.CleanupInterval < 0 {
		return ErrInvalidRateLimitCleanup
	}
	if cfg.EntryRetention < 0 {
		return ErrInvalidRateLimitRetention
	}

	return nil
}

// mustNew creates middleware from static in-repo defaults.
func mustNew(cfg Config) gin.HandlerFunc {
	middleware, err := New(cfg)
	if err != nil {
		panic(err)
	}

	return middleware
}

// newFixedWindowRateLimiter creates an in-memory fixed-window limiter.
func newFixedWindowRateLimiter(
	rule RateLimitRule,
	entryRetention time.Duration,
	cleanupInterval time.Duration,
	now func() time.Time,
) *fixedWindowRateLimiter {
	if now == nil {
		now = time.Now
	}
	if entryRetention == 0 {
		entryRetention = maximumDuration(defaultEntryRetention, rule.Window*2)
	}
	if cleanupInterval == 0 {
		cleanupInterval = defaultCleanupInterval
	}

	return &fixedWindowRateLimiter{
		now:             now,
		rule:            rule,
		entryRetention:  entryRetention,
		cleanupInterval: cleanupInterval,
		lastCleanupAt:   now(),
		entries:         make(map[string]rateLimitEntry),
	}
}

// Allow records a request for the supplied key and returns its rate-limit state.
func (limiter *fixedWindowRateLimiter) Allow(key string) Result {
	if strings.TrimSpace(key) == "" {
		key = defaultUnknownClientKey
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()
	limiter.removeExpiredEntriesIfDue(now)

	entry, exists := limiter.entries[key]
	if !exists || now.Sub(entry.windowStart) >= limiter.rule.Window {
		resetAt := now.Add(limiter.rule.Window)
		limiter.entries[key] = rateLimitEntry{
			windowStart: now,
			lastSeenAt:  now,
			requests:    1,
		}

		return Result{
			Allowed:   true,
			Limit:     limiter.rule.Limit,
			Remaining: limiter.rule.Limit - 1,
			ResetAt:   resetAt,
		}
	}

	entry.lastSeenAt = now
	resetAt := entry.windowStart.Add(limiter.rule.Window)
	if entry.requests < limiter.rule.Limit {
		entry.requests++
		limiter.entries[key] = entry

		return Result{
			Allowed:   true,
			Limit:     limiter.rule.Limit,
			Remaining: limiter.rule.Limit - entry.requests,
			ResetAt:   resetAt,
		}
	}

	limiter.entries[key] = entry
	retryAfter := resetAt.Sub(now)
	if retryAfter < 0 {
		retryAfter = 0
	}

	return Result{
		Allowed:    false,
		Limit:      limiter.rule.Limit,
		Remaining:  0,
		RetryAfter: retryAfter,
		ResetAt:    resetAt,
	}
}

// removeExpiredEntriesIfDue removes old limiter entries during request checks.
func (limiter *fixedWindowRateLimiter) removeExpiredEntriesIfDue(now time.Time) {
	if limiter.cleanupInterval <= 0 {
		return
	}
	if now.Sub(limiter.lastCleanupAt) < limiter.cleanupInterval {
		return
	}

	limiter.lastCleanupAt = now
	cutoff := now.Add(-limiter.entryRetention)
	for key, entry := range limiter.entries {
		if entry.lastSeenAt.Before(cutoff) {
			delete(limiter.entries, key)
		}
	}
}

// setRateLimitHeaders writes standard rate-limit response metadata.
func setRateLimitHeaders(ctx *gin.Context, result Result) {
	ctx.Header("RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
	ctx.Header("RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))

	if !result.ResetAt.IsZero() {
		resetSeconds := int64(math.Ceil(time.Until(result.ResetAt).Seconds()))
		if resetSeconds < 0 {
			resetSeconds = 0
		}
		ctx.Header("RateLimit-Reset", fmt.Sprintf("%d", resetSeconds))
	}

	if !result.Allowed {
		ctx.Header("Retry-After", fmt.Sprintf("%d", retryAfterSeconds(result.RetryAfter)))
	}
}

// retryAfterSeconds rounds retry durations up to a positive whole second.
func retryAfterSeconds(duration time.Duration) int64 {
	seconds := int64(math.Ceil(duration.Seconds()))
	if seconds < 1 {
		return 1
	}

	return seconds
}

// maximumDuration returns the larger duration.
func maximumDuration(left time.Duration, right time.Duration) time.Duration {
	if left > right {
		return left
	}

	return right
}
