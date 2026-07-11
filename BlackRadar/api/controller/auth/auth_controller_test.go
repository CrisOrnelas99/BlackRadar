// Package controller tests authentication controller request handling.
package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"blackradar/api/controller/dto"
	appcontext "blackradar/api/requestContext"
	baseservice "blackradar/api/service"
)

// TestAuthControllerHandlers verifies the auth controller request flow.
func TestAuthControllerHandlers(t *testing.T) {
	svc := &fakeAuthService{loginResponse: dto.LoginResponse{Token: "token", RefreshToken: "refresh", User: dto.UserResponse{ID: "00000000-0000-4000-8000-000000000001", Username: "analyst", Email: "analyst@example.com"}}}
	controller := NewAuthController(svc)

	t.Run("register", func(t *testing.T) {
		ec, recorder := newAuthContext(t, http.MethodPost, "/auth/register", `{"username":"analyst","email":"analyst@example.com","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Register(ec)
		if svc.registerCalls != 1 {
			t.Fatal("expected Register to be called")
		}
		if recorder.Code != http.StatusCreated {
			t.Fatalf("expected %d, got %d", http.StatusCreated, recorder.Code)
		}
		var response dto.UserResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode register response: %v", err)
		}
		if response.ID != "00000000-0000-4000-8000-000000000001" || response.Username != "analyst" || response.Email != "analyst@example.com" {
			t.Fatalf("unexpected register response: %#v", response)
		}
	})

	t.Run("login", func(t *testing.T) {
		ec, _ := newAuthContext(t, http.MethodPost, "/auth/login", `{"userOrEmail":"analyst","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Login(ec)
		if svc.loginCalls != 1 {
			t.Fatal("expected Login to be called")
		}
	})

	t.Run("refresh", func(t *testing.T) {
		ec, _ := newAuthContext(t, http.MethodPost, "/auth/refresh", `{"refreshToken":"refresh"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Refresh(ec)
		if svc.refreshCalls != 1 {
			t.Fatal("expected Refresh to be called")
		}
	})

	t.Run("logout", func(t *testing.T) {
		ec, _ := newAuthContext(t, http.MethodPost, "/auth/logout", `{"refreshToken":"refresh"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Logout(ec)
		if svc.logoutCalls != 1 {
			t.Fatal("expected Logout to be called")
		}
	})
}

type fakeAuthService struct {
	registerResponse dto.UserResponse
	loginResponse    dto.LoginResponse
	registerCalls    int
	loginCalls       int
	refreshCalls     int
	logoutCalls      int
}

func (f *fakeAuthService) Register(ec *appcontext.GinContext, request dto.RegisterRequest) (dto.UserResponse, error) {
	f.registerCalls++
	if f.registerResponse == (dto.UserResponse{}) {
		f.registerResponse = dto.UserResponse{ID: "00000000-0000-4000-8000-000000000001", Username: request.Username, Email: request.Email}
	}
	return f.registerResponse, nil
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
func newAuthContext(t *testing.T, method string, target string, body string) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(method, target, io.NopCloser(strings.NewReader(body)))
	ctx.Request = req
	ec := appcontext.NewGinContext(ctx, "txn-123", nil)
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}
