// Package controller tests authentication controller request handling.
package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	baseservice "secureops/backend-go/api/service"
)

// TestAuthControllerHandlers verifies the auth controller request flow.
func TestAuthControllerHandlers(t *testing.T) {
	svc := &fakeAuthService{loginResponse: dto.LoginResponse{Token: "token", RefreshToken: "refresh", User: dto.UserResponse{ID: 1, Username: "analyst", Email: "analyst@example.com"}}}
	controller := NewAuthController(svc)

	t.Run("register", func(t *testing.T) {
		ec := newAuthContext(t, http.MethodPost, "/auth/register", `{"username":"analyst","email":"analyst@example.com","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Register(ec)
		if svc.registerCalls != 1 {
			t.Fatal("expected Register to be called")
		}
	})

	t.Run("login", func(t *testing.T) {
		ec := newAuthContext(t, http.MethodPost, "/auth/login", `{"userOrEmail":"analyst","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Login(ec)
		if svc.loginCalls != 1 {
			t.Fatal("expected Login to be called")
		}
	})

	t.Run("refresh", func(t *testing.T) {
		ec := newAuthContext(t, http.MethodPost, "/auth/refresh", `{"refreshToken":"refresh"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Refresh(ec)
		if svc.refreshCalls != 1 {
			t.Fatal("expected Refresh to be called")
		}
	})

	t.Run("logout", func(t *testing.T) {
		ec := newAuthContext(t, http.MethodPost, "/auth/logout", `{"refreshToken":"refresh"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Logout(ec)
		if svc.logoutCalls != 1 {
			t.Fatal("expected Logout to be called")
		}
	})
}

type fakeAuthService struct {
	loginResponse dto.LoginResponse
	registerCalls int
	loginCalls    int
	refreshCalls  int
	logoutCalls   int
}

func (f *fakeAuthService) Register(ec *appcontext.GinContext, request dto.RegisterRequest) error {
	f.registerCalls++
	return nil
}

func (f *fakeAuthService) Login(ec *appcontext.GinContext, request dto.LoginRequest) (dto.LoginResponse, error) {
	f.loginCalls++
	return f.loginResponse, nil
}

func (f *fakeAuthService) Refresh(ec *appcontext.GinContext, request dto.RefreshRequest) (dto.LoginResponse, error) {
	f.refreshCalls++
	return f.loginResponse, nil
}

func (f *fakeAuthService) Logout(ec *appcontext.GinContext, request dto.RefreshRequest) error {
	f.logoutCalls++
	return nil
}

var _ baseservice.AuthService = (*fakeAuthService)(nil)

// newAuthContext creates a test Gin context for auth controller tests.
func newAuthContext(t *testing.T, method string, target string, body string) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(method, target, io.NopCloser(strings.NewReader(body)))
	ctx.Request = req
	ec := appcontext.NewGinContext(ctx, "txn-123", nil)
	appcontext.SetGinContext(ctx, ec)
	return ec
}
