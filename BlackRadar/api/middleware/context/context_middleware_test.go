package contextmiddleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	appcontext "blackradar/api/context"
)

func TestRequestContextStoresGinContextAndContinues(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestContext())
	router.GET("/resource", func(ctx *gin.Context) {
		ec, err := appcontext.FromGinContext(ctx)
		if err != nil {
			t.Fatalf("expected request context, got %v", err)
		}

		if ec.Context != ctx {
			t.Fatal("expected request context to wrap current Gin context")
		}
		if ec.TransactionID() == "" {
			t.Fatal("expected transaction ID to be set")
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
}
