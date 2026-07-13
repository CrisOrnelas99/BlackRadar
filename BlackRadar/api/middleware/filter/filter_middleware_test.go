package filter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestFilterAllowsNormalRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestFilter())
	router.GET("/assets", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/assets?status=open", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestRequestFilterDoesNotBlockQueryTextAsSecurityPattern(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestFilter())
	router.GET("/search", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/search?q=union+select+drop+table", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestRequestFilterRejectsUnsafePaths(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "plain traversal", target: "/assets/../secret"},
		{name: "encoded traversal", target: "/assets/%2e%2e/secret"},
		{name: "backslash traversal", target: `/assets\..\secret`},
		{name: "encoded control character", target: "/assets/%00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(RequestFilter())
			router.GET("/*path", func(ctx *gin.Context) {
				t.Fatal("handler should not run for unsafe request path")
			})

			recorder := performRequest(router, http.MethodGet, tt.target, nil)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
			}
			if recorder.Body.String() != `{"error":"invalid request path"}` {
				t.Fatalf("unexpected response body: %q", recorder.Body.String())
			}
		})
	}
}

func TestValidatePathReturnsSentinelErrors(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		maxLength int
		sentinel  error
	}{
		{
			name:      "path too long",
			path:      "/" + strings.Repeat("a", defaultMaximumPathLength),
			maxLength: defaultMaximumPathLength,
			sentinel:  ErrRequestPathTooLong,
		},
		{
			name:      "control character",
			path:      "/assets/%00",
			maxLength: defaultMaximumPathLength,
			sentinel:  ErrRequestPathControlChar,
		},
		{
			name:      "bad encoding",
			path:      "/assets/%zz",
			maxLength: defaultMaximumPathLength,
			sentinel:  ErrRequestPathBadEncoding,
		},
		{
			name:      "traversal",
			path:      "/assets/%2e%2e/secret",
			maxLength: defaultMaximumPathLength,
			sentinel:  ErrRequestPathTraversal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePath(tt.path, tt.maxLength)

			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("expected %v, got %v", tt.sentinel, err)
			}
		})
	}
}

func performRequest(router http.Handler, method string, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, nil)
	if mutate != nil {
		mutate(request)
	}
	router.ServeHTTP(recorder, request)
	return recorder
}
