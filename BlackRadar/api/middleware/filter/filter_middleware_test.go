package filter

import (
	"net/http"
	"net/http/httptest"
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

func TestRequestFilterBlocksSuspiciousRequests(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		rawQuery string
	}{
		{name: "path traversal", target: "/assets", rawQuery: "file=../secret"},
		{name: "encoded script tag", target: "/assets", rawQuery: "q=%3Cscript%3Ealert(1)%3C/script%3E"},
		{name: "sql injection", target: "/assets", rawQuery: "q=' or 1=1"},
		{name: "drop table", target: "/assets", rawQuery: "q=drop table users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(RequestFilter())
			router.GET("/assets", func(ctx *gin.Context) {
				t.Fatal("handler should not run for suspicious request")
			})

			recorder := performRequest(router, http.MethodGet, tt.target, func(request *http.Request) {
				request.URL.RawQuery = tt.rawQuery
			})

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
			}
			if recorder.Body.String() != `{"error":"Request blocked"}` {
				t.Fatalf("unexpected response body: %q", recorder.Body.String())
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
