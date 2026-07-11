package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestFixedWindowRateLimiterBlocksAfterLimit(t *testing.T) {
	current := time.Unix(0, 0)
	limiter := newFixedWindowRateLimiter(RateLimitRule{
		Name:   "auth",
		Limit:  2,
		Window: time.Minute,
	}, func() time.Time {
		return current
	})

	if allowed, _ := limiter.Allow("203.0.113.10"); !allowed {
		t.Fatal("expected first request to be allowed")
	}
	if allowed, _ := limiter.Allow("203.0.113.10"); !allowed {
		t.Fatal("expected second request to be allowed")
	}
	if allowed, retryAfter := limiter.Allow("203.0.113.10"); allowed || retryAfter <= 0 {
		t.Fatalf("expected third request to be blocked with retry-after, got allowed=%v retryAfter=%v", allowed, retryAfter)
	}

	current = current.Add(time.Minute)
	if allowed, _ := limiter.Allow("203.0.113.10"); !allowed {
		t.Fatal("expected requests to be allowed after the window resets")
	}
}

func TestAuthRateLimitMiddlewareReturns429(t *testing.T) {
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

func performRequest(router http.Handler, method string, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, nil)
	router.ServeHTTP(recorder, request)
	return recorder
}
