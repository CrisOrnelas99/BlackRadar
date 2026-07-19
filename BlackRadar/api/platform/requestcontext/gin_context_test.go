package requestcontext

import (
	stdcontext "context"
	"errors"
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
	if ctx.RequestID() != "txn-123" {
		t.Fatalf("expected request ID txn-123, got %q", ctx.RequestID())
	}
	if ctx.Logger() != logger {
		t.Fatal("expected logger to be stored")
	}
}

func TestSetGinContextAndFromGinContextReturnStoredContext(t *testing.T) {
	ginCtx := newTestGinContext(t)
	expected := NewGinContext(ginCtx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))

	SetGinContext(ginCtx, expected)

	actual, err := FromGinContext(ginCtx)
	if err != nil {
		t.Fatalf("expected stored GinContext, got %v", err)
	}
	if actual != expected {
		t.Fatal("expected stored GinContext to be returned")
	}
}

func TestFromGinContextRejectsMissingOrWrongType(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*gin.Context)
	}{
		{name: "missing"},
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

			_, err := FromGinContext(ginCtx)
			if !errors.Is(err, ErrContextNotInitialized) {
				t.Fatalf("expected ErrContextNotInitialized, got %v", err)
			}
		})
	}
}

func TestWrapRejectsMissingRequestContext(t *testing.T) {
	ginCtx := newTestGinContext(t)
	handlerCalled := false

	Wrap(func(ctx *GinContext) {
		handlerCalled = true
	})(ginCtx)

	if handlerCalled {
		t.Fatal("expected wrapped handler not to run without request context")
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

func TestPrincipalAccessorsRequireExplicitAuthentication(t *testing.T) {
	ginCtx := newTestGinContext(t)
	ctx := NewGinContext(ginCtx, "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := ctx.Principal(); !errors.Is(err, ErrPrincipalNotSet) {
		t.Fatalf("expected ErrPrincipalNotSet, got %v", err)
	}
	if _, err := ctx.UserID(); !errors.Is(err, ErrPrincipalNotSet) {
		t.Fatalf("expected ErrPrincipalNotSet for user ID, got %v", err)
	}
	if _, err := ctx.Username(); !errors.Is(err, ErrPrincipalNotSet) {
		t.Fatalf("expected ErrPrincipalNotSet for username, got %v", err)
	}
	if _, err := ctx.UserRole(); !errors.Is(err, ErrPrincipalNotSet) {
		t.Fatalf("expected ErrPrincipalNotSet for role, got %v", err)
	}
	if _, err := ctx.OrganizationID(); !errors.Is(err, ErrPrincipalNotSet) {
		t.Fatalf("expected ErrPrincipalNotSet for organization ID, got %v", err)
	}
}

func TestSetPrincipalStoresValidatedIdentity(t *testing.T) {
	ginCtx := newTestGinContext(t)
	ctx := NewGinContext(ginCtx, "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := ctx.SetPrincipal(Principal{
		UserID:         "00000000-0000-4000-8000-000000000042",
		Username:       "analyst",
		Role:           "user",
		OrganizationID: "00000000-0000-4000-8000-000000000077",
	})
	if err != nil {
		t.Fatalf("expected principal to be accepted, got %v", err)
	}

	userID, err := ctx.UserID()
	if err != nil || userID != "00000000-0000-4000-8000-000000000042" {
		t.Fatalf("expected user UUID, got %q error=%v", userID, err)
	}
	username, err := ctx.Username()
	if err != nil || username != "analyst" {
		t.Fatalf("expected username analyst, got %q error=%v", username, err)
	}
	role, err := ctx.UserRole()
	if err != nil || role != "user" {
		t.Fatalf("expected user role user, got %q error=%v", role, err)
	}
	organizationID, err := ctx.OrganizationID()
	if err != nil || organizationID != "00000000-0000-4000-8000-000000000077" {
		t.Fatalf("expected organization UUID, got %q error=%v", organizationID, err)
	}
}

func TestSetPrincipalRejectsInvalidIdentity(t *testing.T) {
	ginCtx := newTestGinContext(t)
	ctx := NewGinContext(ginCtx, "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := ctx.SetPrincipal(Principal{
		Username: "analyst",
		Role:     "user",
	})
	if !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("expected ErrInvalidPrincipal, got %v", err)
	}
}

func TestCompatibilitySettersRequireCompletePrincipalForReads(t *testing.T) {
	ginCtx := newTestGinContext(t)
	ctx := NewGinContext(ginCtx, "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx.SetUserRole("admin")
	if _, err := ctx.UserRole(); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("expected ErrInvalidPrincipal, got %v", err)
	}

	ctx.SetUserID("00000000-0000-4000-8000-000000000042")
	ctx.SetOrganizationID("00000000-0000-4000-8000-000000000077")
	ctx.SetUsername("analyst")

	role, err := ctx.UserRole()
	if err != nil || role != "admin" {
		t.Fatalf("expected role admin, got %q error=%v", role, err)
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
