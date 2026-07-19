package contextmiddleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	appcontext "blackradar/api/platform/requestcontext"
)

func TestRequestContextStoresGinContextAndContinues(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestContext(nil))
	router.GET("/resource", func(ctx *gin.Context) {
		ec, err := appcontext.FromGinContext(ctx)
		if err != nil {
			t.Fatalf("expected request context, got %v", err)
		}

		if ec.Context != ctx {
			t.Fatal("expected request context to wrap current Gin context")
		}
		if ec.RequestID() == "" {
			t.Fatal("expected request ID to be set")
		}
		if ec.Logger() == nil {
			t.Fatal("expected logger to be set")
		}

		ctx.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/resource", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if recorder.Header().Get(requestIDHeader) == "" {
		t.Fatal("expected request ID response header to be set")
	}
}

func TestClientRequestIDValidatesHeader(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{name: "missing"},
		{name: "valid", header: "request_123.ABC-xyz", expected: "request_123.ABC-xyz"},
		{name: "too long", header: string(make([]byte, 129))},
		{name: "newline", header: "request\n123"},
		{name: "space", header: "request 123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, "/resource", nil)
			if tt.header != "" {
				ctx.Request.Header.Set(requestIDHeader, tt.header)
			}

			actual := ClientRequestID(ctx)
			if actual != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, actual)
			}
		})
	}
}
