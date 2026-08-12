// Package ratelimit provides request rate-limiting middleware.
package ratelimit

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	basecontroller "blackradar/api/controller/shared"
)

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

		logRateLimitExceeded(ctx, cfg.Rule, result)

		ctx.AbortWithStatusJSON(http.StatusTooManyRequests, basecontroller.ErrorResponse{
			Code:      "RATE_LIMITED",
			Message:   ErrRateLimited.Error(),
			RequestID: requestIDFromContext(ctx),
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

// LoginRateLimit throttles login attempts more aggressively than the broader auth group.
func LoginRateLimit() gin.HandlerFunc {
	return mustNew(Config{
		Rule: RateLimitRule{
			Name:   "auth_login",
			Limit:  5,
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
		Key: PrincipalUserKey,
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
		Key: PrincipalUserKey,
	})
}

// VulnerabilityMutationRateLimit throttles vulnerability create, update, and delete requests.
func VulnerabilityMutationRateLimit() gin.HandlerFunc {
	return mustNew(Config{
		Rule: RateLimitRule{
			Name:   "vulnerability_mutation",
			Limit:  30,
			Window: defaultRateLimitWindow,
		},
		Key: PrincipalUserKey,
	})
}
