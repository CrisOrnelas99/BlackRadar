// Package controller tests user controller request handling.
package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	userservice "blackradar/api/service/user"
)

// TestUserControllerHandlers verifies the user controller request flow.
func TestUserControllerHandlers(t *testing.T) {
	svc := &fakeUserService{loginResponse: userservice.LoginResult{Token: "token", RefreshToken: "refresh", User: model.User{Model: model.Model{ID: "00000000-0000-4000-8000-000000000001"}, Username: "analyst", Email: "analyst@example.com"}}}
	controller := NewUserController(svc)

	t.Run("register", func(t *testing.T) {
		ec, recorder := newUserContext(t, http.MethodPost, "/auth/register", `{"username":"analyst","email":"analyst@example.com","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Register(ec)
		if svc.registerCalls != 1 {
			t.Fatal("expected Register to be called")
		}
		if recorder.Code != http.StatusCreated {
			t.Fatalf("expected %d, got %d", http.StatusCreated, recorder.Code)
		}
		var response UserResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode register response: %v", err)
		}
		if response.ID != "00000000-0000-4000-8000-000000000001" || response.Username != "analyst" || response.Email != "analyst@example.com" {
			t.Fatalf("unexpected register response: %#v", response)
		}
	})

	t.Run("login", func(t *testing.T) {
		ec, _ := newUserContext(t, http.MethodPost, "/auth/login", `{"userOrEmail":"analyst","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Login(ec)
		if svc.loginCalls != 1 {
			t.Fatal("expected Login to be called")
		}
	})

	t.Run("refresh", func(t *testing.T) {
		ec, _ := newUserContext(t, http.MethodPost, "/auth/refresh", `{"refreshToken":"refresh"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Refresh(ec)
		if svc.refreshCalls != 1 {
			t.Fatal("expected Refresh to be called")
		}
	})

	t.Run("logout", func(t *testing.T) {
		ec, _ := newUserContext(t, http.MethodPost, "/auth/logout", `{"refreshToken":"refresh"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Logout(ec)
		if svc.logoutCalls != 1 {
			t.Fatal("expected Logout to be called")
		}
	})
}

func TestRegisterRoutes(t *testing.T) {
	service := &fakeUserService{}
	controller := NewUserController(service)
	engine := gin.New()
	engine.Use(contextmiddleware.RequestContext(nil))
	RegisterRoutes(engine.Group("/api/auth"), controller)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", strings.NewReader(`{"refreshToken":"refresh"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected refresh status %d, got %d", http.StatusOK, recorder.Code)
	}
	if service.refreshCalls != 1 {
		t.Fatalf("expected Refresh to be called once, got %d", service.refreshCalls)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/auth/logout", strings.NewReader(`{"refreshToken":"refresh"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logout status %d, got %d", http.StatusOK, recorder.Code)
	}
	if service.logoutCalls != 1 {
		t.Fatalf("expected Logout to be called once, got %d", service.logoutCalls)
	}
}

type fakeUserService struct {
	registerResponse model.User
	loginResponse    userservice.LoginResult
	registerCalls    int
	loginCalls       int
	refreshCalls     int
	logoutCalls      int
}

func (f *fakeUserService) Register(ec *appcontext.GinContext, request userservice.RegisterInput) (model.User, error) {
	f.registerCalls++
	if f.registerResponse == (model.User{}) {
		f.registerResponse = model.User{Model: model.Model{ID: "00000000-0000-4000-8000-000000000001"}, Username: request.Username, Email: request.Email}
	}
	return f.registerResponse, nil
}

func (f *fakeUserService) Login(ec *appcontext.GinContext, request userservice.LoginInput) (userservice.LoginResult, error) {
	f.loginCalls++
	return f.loginResponse, nil
}

func (f *fakeUserService) Refresh(ec *appcontext.GinContext, request userservice.RefreshInput) (userservice.LoginResult, error) {
	f.refreshCalls++
	return f.loginResponse, nil
}

func (f *fakeUserService) Logout(ec *appcontext.GinContext, request userservice.RefreshInput) error {
	f.logoutCalls++
	return nil
}

var _ userservice.UserService = (*fakeUserService)(nil)

// newUserContext creates a test Gin context for user controller tests.
func newUserContext(t *testing.T, method string, target string, body string) (*appcontext.GinContext, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(method, target, io.NopCloser(strings.NewReader(body)))
	ctx.Request = req
	ec := appcontext.NewGinContext(ctx, "txn-123", nil)
	appcontext.SetGinContext(ctx, ec)
	return ec, recorder
}
