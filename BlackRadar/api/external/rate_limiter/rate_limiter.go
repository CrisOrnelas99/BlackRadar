// Package ratelimiter provides shared outbound client throttling primitives.
//
// This is not Gin middleware. It is an in-process limiter used by external
// provider clients before they make outbound requests. Inbound HTTP throttling
// remains in api/middleware/rate_limit.
package ratelimiter

import (
	"sync"
	"time"
)

// RateLimiter limits outbound provider requests in a rolling window.
type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	requests []time.Time
}

// NewRateLimiter creates a rolling-window limiter.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 1
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	return &RateLimiter{limit: limit, window: window}
}

// Allow records a request when capacity remains in the rolling window.
func (r *RateLimiter) Allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := now.Add(-r.window)
	kept := r.requests[:0]
	for _, requestTime := range r.requests {
		if requestTime.After(cutoff) {
			kept = append(kept, requestTime)
		}
	}
	r.requests = kept

	if len(r.requests) >= r.limit {
		return false
	}
	r.requests = append(r.requests, now)
	return true
}
