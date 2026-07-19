package ratelimit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	contextmiddleware "blackradar/api/middleware/context"
	requestcontext "blackradar/api/platform/requestcontext"
)

func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		sentinel error
	}{
		{name: "missing rule name", config: Config{Rule: RateLimitRule{Limit: 1, Window: time.Minute}}, sentinel: ErrRateLimitNameRequired},
		{name: "invalid limit", config: Config{Rule: RateLimitRule{Name: "auth", Window: time.Minute}}, sentinel: ErrInvalidRateLimit},
		{name: "invalid window", config: Config{Rule: RateLimitRule{Name: "auth", Limit: 1}}, sentinel: ErrInvalidRateLimitWindow},
		{name: "negative cleanup interval", config: Config{Rule: RateLimitRule{Name: "auth", Limit: 1, Window: time.Minute}, CleanupInterval: -time.Second}, sentinel: ErrInvalidRateLimitCleanup},
		{name: "negative retention", config: Config{Rule: RateLimitRule{Name: "auth", Limit: 1, Window: time.Minute}, EntryRetention: -time.Second}, sentinel: ErrInvalidRateLimitRetention},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := New(tt.config)

			if middleware != nil {
				t.Fatal("expected middleware to be nil")
			}
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("expected error to match %v, got %v", tt.sentinel, err)
			}
		})
	}
}

func TestFixedWindowRateLimiterBlocksAfterLimit(t *testing.T) {
	current := time.Unix(100, 0)
	limiter := newFixedWindowRateLimiter(
		RateLimitRule{Name: "auth", Limit: 2, Window: time.Minute},
		0,
		0,
		func() time.Time {
			return current
		},
	)

	first := limiter.Allow("203.0.113.10")
	if !first.Allowed || first.Remaining != 1 {
		t.Fatalf("expected first request to be allowed with one remaining, got %+v", first)
	}

	second := limiter.Allow("203.0.113.10")
	if !second.Allowed || second.Remaining != 0 {
		t.Fatalf("expected second request to be allowed with zero remaining, got %+v", second)
	}

	third := limiter.Allow("203.0.113.10")
	if third.Allowed || third.RetryAfter <= 0 {
		t.Fatalf("expected third request to be blocked with retry-after, got %+v", third)
	}

	current = current.Add(time.Minute)
	reset := limiter.Allow("203.0.113.10")
	if !reset.Allowed || reset.Remaining != 1 {
		t.Fatalf("expected request to be allowed after the window resets, got %+v", reset)
	}
}

func TestFixedWindowRateLimiterRemovesExpiredEntries(t *testing.T) {
	current := time.Unix(100, 0)
	limiter := newFixedWindowRateLimiter(
		RateLimitRule{Name: "auth", Limit: 2, Window: time.Minute},
		time.Minute,
		time.Second,
		func() time.Time {
			return current
		},
	)

	limiter.Allow("old-client")
	if len(limiter.entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(limiter.entries))
	}

	current = current.Add(2 * time.Minute)
	limiter.Allow("new-client")

	if _, exists := limiter.entries["old-client"]; exists {
		t.Fatal("expected expired entry to be removed")
	}
	if _, exists := limiter.entries["new-client"]; !exists {
		t.Fatal("expected new entry to remain")
	}
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	if seconds := retryAfterSeconds(500 * time.Millisecond); seconds != 1 {
		t.Fatalf("expected sub-second retry to round up to 1, got %d", seconds)
	}
	if seconds := retryAfterSeconds(1500 * time.Millisecond); seconds != 2 {
		t.Fatalf("expected retry to round up to 2, got %d", seconds)
	}
}

func TestAuthRateLimitMiddlewareReturns429WithHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(AuthRateLimit())
	router.GET("/resource", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	for i := 0; i < 10; i++ {
		recorder := performRequest(router, http.MethodGet, "/resource")
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected request %d to be allowed, got %d", i+1, recorder.Code)
		}
	}

	recorder := performRequest(router, http.MethodGet, "/resource")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate-limited request to return %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
	if recorder.Header().Get("RateLimit-Limit") != "10" {
		t.Fatalf("expected RateLimit-Limit 10, got %q", recorder.Header().Get("RateLimit-Limit"))
	}
	if recorder.Header().Get("RateLimit-Remaining") != "0" {
		t.Fatalf("expected RateLimit-Remaining 0, got %q", recorder.Header().Get("RateLimit-Remaining"))
	}
}

func TestAIRateLimitMiddlewareReturns429(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(AIRateLimit())
	router.GET("/ai", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		recorder := performRequest(router, http.MethodGet, "/ai")
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected request %d to be allowed, got %d", i+1, recorder.Code)
		}
	}

	recorder := performRequest(router, http.MethodGet, "/ai")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate-limited request to return %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}
}

func TestPrincipalUserKeyUsesAuthenticatedUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil))
	router.GET("/resource", func(ctx *gin.Context) {
		ec, err := requestcontext.FromGinContext(ctx)
		if err != nil {
			t.Fatalf("expected request context, got %v", err)
		}
		if err := ec.SetPrincipal(requestcontext.Principal{
			UserID: "00000000-0000-4000-8000-000000000001",
		}); err != nil {
			t.Fatalf("failed to set principal: %v", err)
		}

		if key := PrincipalUserKey(ctx); key != "user:00000000-0000-4000-8000-000000000001" {
			t.Fatalf("unexpected key %q", key)
		}
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/resource")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func performRequest(router http.Handler, method string, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, nil)
	router.ServeHTTP(recorder, request)
	return recorder
}
