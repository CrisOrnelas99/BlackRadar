// Package ratelimiter verifies outbound rolling-window throttling.
package ratelimiter

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsAfterWindowExpires(t *testing.T) {
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)

	limiter := NewRateLimiter(1, time.Minute)
	if !limiter.Allow(now) {
		t.Fatal("expected first request to be allowed")
	}
	if limiter.Allow(now.Add(time.Second)) {
		t.Fatal("expected second request inside the window to be rejected")
	}
	if !limiter.Allow(now.Add(time.Minute + time.Second)) {
		t.Fatal("expected request after the window to be allowed")
	}
}

func TestNewRateLimiterNormalizesInvalidConfig(t *testing.T) {
	limiter := NewRateLimiter(0, 0)
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)

	if !limiter.Allow(now) {
		t.Fatal("expected first request to be allowed with normalized defaults")
	}
	if limiter.Allow(now.Add(time.Second)) {
		t.Fatal("expected default limit of one request per default window")
	}
}
