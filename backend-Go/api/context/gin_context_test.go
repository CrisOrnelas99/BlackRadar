package context

import (
	stdcontext "context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func TestNewGinContextStoresRequestScopedValues(t *testing.T) {
	ginCtx := newTestGinContext(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx := NewGinContext(ginCtx, "txn-123", logger)

	if ctx.Context != ginCtx {
		t.Fatal("expected Gin context to be stored")
	}
	if ctx.TransactionID() != "txn-123" {
		t.Fatalf("expected transaction ID txn-123, got %q", ctx.TransactionID())
	}
	if ctx.Logger() != logger {
		t.Fatal("expected logger to be stored")
	}
}

func TestSetGinContextAndFromGinContextReturnStoredContext(t *testing.T) {
	ginCtx := newTestGinContext(t)
	expected := NewGinContext(ginCtx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))

	SetGinContext(ginCtx, expected)

	actual := FromGinContext(ginCtx)

	if actual != expected {
		t.Fatal("expected stored GinContext to be returned")
	}
}

func TestFromGinContextFallsBackWhenMissingOrWrongType(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*gin.Context)
	}{
		{
			name: "missing",
		},
		{
			name: "wrong type",
			setup: func(ctx *gin.Context) {
				ctx.Set(ginContextKey, "not a GinContext")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ginCtx := newTestGinContext(t)
			if tt.setup != nil {
				tt.setup(ginCtx)
			}

			actual := FromGinContext(ginCtx)

			if actual == nil {
				t.Fatal("expected fallback GinContext")
			}
			if actual.Context != ginCtx {
				t.Fatal("expected fallback to wrap original Gin context")
			}
			if actual.TransactionID() != "" {
				t.Fatalf("expected empty fallback transaction ID, got %q", actual.TransactionID())
			}
			if actual.Logger() == nil {
				t.Fatal("expected fallback logger")
			}
		})
	}
}

func TestWrapPassesGinContextToHandler(t *testing.T) {
	ginCtx := newTestGinContext(t)
	expected := NewGinContext(ginCtx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	SetGinContext(ginCtx, expected)

	var actual *GinContext
	handler := Wrap(func(ctx *GinContext) {
		actual = ctx
	})

	handler(ginCtx)

	if actual != expected {
		t.Fatal("expected wrapped handler to receive stored GinContext")
	}
}

func TestAuthenticatedUserValuesReturnExpectedTypesOnly(t *testing.T) {
	ginCtx := newTestGinContext(t)
	ctx := NewGinContext(ginCtx, "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if ctx.UserID() != 0 {
		t.Fatalf("expected missing user ID to return 0, got %d", ctx.UserID())
	}
	if ctx.Username() != "" {
		t.Fatalf("expected missing username to return empty string, got %q", ctx.Username())
	}
	if ctx.UserRole() != "" {
		t.Fatalf("expected missing user role to return empty string, got %q", ctx.UserRole())
	}
	if ctx.OrganizationID() != 0 {
		t.Fatalf("expected missing organization ID to return 0, got %d", ctx.OrganizationID())
	}

	ctx.SetUserID(int64(42))
	ctx.SetUsername("analyst")
	ctx.SetUserRole("user")
	ctx.SetOrganizationID(int64(77))

	if ctx.UserID() != 42 {
		t.Fatalf("expected user ID 42, got %d", ctx.UserID())
	}
	if ctx.Username() != "analyst" {
		t.Fatalf("expected username analyst, got %q", ctx.Username())
	}
	if ctx.UserRole() != "user" {
		t.Fatalf("expected user role user, got %q", ctx.UserRole())
	}
	if ctx.OrganizationID() != 77 {
		t.Fatalf("expected organization ID 77, got %d", ctx.OrganizationID())
	}

	ctx.Set(userIDKey, "42")
	ctx.Set(usernameKey, 42)
	ctx.Set(userRoleKey, 42)
	ctx.Set(organizationIDKey, "77")

	if ctx.UserID() != 0 {
		t.Fatalf("expected wrong-type user ID to return 0, got %d", ctx.UserID())
	}
	if ctx.Username() != "" {
		t.Fatalf("expected wrong-type username to return empty string, got %q", ctx.Username())
	}
	if ctx.UserRole() != "" {
		t.Fatalf("expected wrong-type user role to return empty string, got %q", ctx.UserRole())
	}
	if ctx.OrganizationID() != 0 {
		t.Fatalf("expected wrong-type organization ID to return 0, got %d", ctx.OrganizationID())
	}
}

func TestDatabaseAccessors(t *testing.T) {
	ctx := NewGinContext(newTestGinContext(t), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	database := &gorm.DB{}

	if ctx.Database() != nil {
		t.Fatal("expected database to be nil before it is set")
	}

	ctx.SetDatabase(database)

	if ctx.Database() != database {
		t.Fatal("expected database accessor to return stored database")
	}
}

func TestRequestContextReturnsHTTPRequestContext(t *testing.T) {
	requestCtx := stdcontext.WithValue(stdcontext.Background(), testRequestContextKey{}, "value")
	request := httptest.NewRequest(http.MethodGet, "/resource", nil).WithContext(requestCtx)
	ginCtx := newTestGinContextWithRequest(t, request)
	ctx := NewGinContext(ginCtx, "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	actual := ctx.RequestContext()

	if actual != requestCtx {
		t.Fatal("expected request context to come from the HTTP request")
	}
	if actual.Value(testRequestContextKey{}) != "value" {
		t.Fatal("expected request context value to be preserved")
	}
}

type testRequestContextKey struct{}

func newTestGinContext(t *testing.T) *gin.Context {
	t.Helper()

	return newTestGinContextWithRequest(t, httptest.NewRequest(http.MethodGet, "/resource", nil))
}

func newTestGinContextWithRequest(t *testing.T, request *http.Request) *gin.Context {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request

	return ctx
}
