// Package controller tests user controller request handling.
package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	userservice "blackradar/api/service/user"
)

// TestUserControllerHandlers verifies the user controller request flow.
func TestUserControllerHandlers(t *testing.T) {
	svc := &fakeUserService{loginResponse: testLoginResult()}
	controller := NewUserController(svc, false)

	t.Run("create user", func(t *testing.T) {
		ec, recorder := newUserContext(t, http.MethodPost, "/users", `{"fullName":"Analyst User","username":"analyst","email":"analyst@example.com","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.CreateUser(ec)
		if svc.createUserCalls != 1 {
			t.Fatal("expected CreateUser to be called")
		}
		if recorder.Code != http.StatusCreated {
			t.Fatalf("expected %d, got %d", http.StatusCreated, recorder.Code)
		}
		var response UserResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode create user response: %v", err)
		}
		if response.ID != "00000000-0000-4000-8000-000000000001" || response.FullName != "Analyst User" || response.Username != "analyst" || response.Email != "analyst@example.com" {
			t.Fatalf("unexpected create user response: %#v", response)
		}
	})

	t.Run("create user conflict is generic", func(t *testing.T) {
		tests := []struct {
			name string
			err  error
		}{
			{name: "duplicate username", err: userservice.ErrUsernameAlreadyExists},
			{name: "duplicate email", err: userservice.ErrEmailAlreadyExists},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc.createUserErr = tt.err
				ec, recorder := newUserContext(t, http.MethodPost, "/users", `{"fullName":"Analyst User","username":"analyst","email":"analyst@example.com","password":"Password1!"}`)
				ec.Request.Header.Set("Content-Type", "application/json")

				controller.CreateUser(ec)

				if recorder.Code != http.StatusConflict {
					t.Fatalf("expected %d, got %d", http.StatusConflict, recorder.Code)
				}

				var response map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to decode conflict response: %v", err)
				}

				if got := response["message"]; got != "User already exists." {
					t.Fatalf("expected generic user conflict message, got %#v", got)
				}
				if body := recorder.Body.String(); strings.Contains(body, "username already exists") || strings.Contains(body, "email already exists") {
					t.Fatalf("expected generic conflict response, got %s", body)
				}
			})
		}
	})

	t.Run("login", func(t *testing.T) {
		ec, recorder := newUserContext(t, http.MethodPost, "/auth/login", `{"userOrEmail":"analyst","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Login(ec)
		if svc.loginCalls != 1 {
			t.Fatal("expected Login to be called")
		}
		if got := recorder.Header().Get("Set-Cookie"); !strings.Contains(got, refreshTokenCookieName+"=refresh") || !strings.Contains(got, "HttpOnly") {
			t.Fatalf("expected HttpOnly refresh cookie, got %q", got)
		}
		var response map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to decode login response: %v", err)
		}
		if _, exists := response["refreshToken"]; exists {
			t.Fatalf("expected response body to omit refresh token, got %s", recorder.Body.String())
		}
	})

	t.Run("login uses a secure refresh cookie in production", func(t *testing.T) {
		secureController := NewUserController(svc, true)
		ec, recorder := newUserContext(t, http.MethodPost, "/auth/login", `{"userOrEmail":"analyst","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		secureController.Login(ec)

		cookie := recorder.Result().Cookies()[0]
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != refreshTokenCookiePath {
			t.Fatalf("unexpected refresh cookie attributes: %#v", cookie)
		}
	})

	t.Run("login backoff returns too many requests", func(t *testing.T) {
		svc.loginErr = userservice.ErrLoginBackoff
		ec, recorder := newUserContext(t, http.MethodPost, "/auth/login", `{"userOrEmail":"analyst","password":"Password1!"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.Login(ec)

		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("expected %d, got %d", http.StatusTooManyRequests, recorder.Code)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		ec, _ := newUserContext(t, http.MethodPost, "/auth/refresh", "")
		ec.Request.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "refresh"})
		controller.Refresh(ec)
		if svc.refreshCalls != 1 {
			t.Fatal("expected Refresh to be called")
		}
		if svc.refreshToken != "refresh" {
			t.Fatalf("expected refresh token from cookie, got %q", svc.refreshToken)
		}
	})

	t.Run("refresh without a cookie does not call the service", func(t *testing.T) {
		ec, recorder := newUserContext(t, http.MethodPost, "/auth/refresh", "")
		controller.Refresh(ec)
		if svc.refreshCalls != 1 {
			t.Fatalf("expected Refresh call count to remain unchanged, got %d", svc.refreshCalls)
		}
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected refresh without cookie status %d, got %d", http.StatusUnauthorized, recorder.Code)
		}
	})

	t.Run("logout", func(t *testing.T) {
		ec, recorder := newUserContext(t, http.MethodPost, "/auth/logout", "")
		ec.Request.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "refresh"})
		controller.Logout(ec)
		if svc.logoutCalls != 1 {
			t.Fatal("expected Logout to be called")
		}
		if svc.logoutToken != "refresh" {
			t.Fatalf("expected logout token from cookie, got %q", svc.logoutToken)
		}
		if got := recorder.Header().Get("Set-Cookie"); !strings.Contains(got, refreshTokenCookieName+"=") || !strings.Contains(got, "Max-Age=0") {
			t.Fatalf("expected refresh cookie to be cleared, got %q", got)
		}
	})

	t.Run("logout without cookie clears client session", func(t *testing.T) {
		ec, recorder := newUserContext(t, http.MethodPost, "/auth/logout", "")
		controller.Logout(ec)
		if svc.logoutCalls != 1 {
			t.Fatal("expected Logout call count to remain unchanged")
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected logout without cookie status %d, got %d", http.StatusOK, recorder.Code)
		}
		if got := recorder.Header().Get("Set-Cookie"); !strings.Contains(got, refreshTokenCookieName+"=") || !strings.Contains(got, "Max-Age=0") {
			t.Fatalf("expected refresh cookie to be cleared, got %q", got)
		}
	})
}

func TestAuthRoutes(t *testing.T) {
	service := &fakeUserService{}
	controller := NewUserController(service, false)
	engine := gin.New()
	engine.Use(contextmiddleware.RequestContext(nil))
	RegisterRoutes(engine.Group("/api/auth"), controller)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	request.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "refresh"})
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected refresh status %d, got %d", http.StatusOK, recorder.Code)
	}
	if service.refreshCalls != 1 {
		t.Fatalf("expected Refresh to be called once, got %d", service.refreshCalls)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "refresh"})
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logout status %d, got %d", http.StatusOK, recorder.Code)
	}
	if service.logoutCalls != 1 {
		t.Fatalf("expected Logout to be called once, got %d", service.logoutCalls)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/auth/register", nil)
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected public user creation route to be absent, got %d", recorder.Code)
	}
}

func TestRegisterAdminRoutes(t *testing.T) {
	service := &fakeUserService{}
	controller := NewUserController(service, false)
	engine := gin.New()
	engine.Use(contextmiddleware.RequestContext(nil))
	RegisterAdminRoutes(engine.Group("/api"), controller)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"fullName":"Analyst User","username":"analyst","email":"analyst@example.com","password":"Password1!"}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected create user status %d, got %d", http.StatusCreated, recorder.Code)
	}
	if service.createUserCalls != 1 {
		t.Fatalf("expected CreateUser to be called once, got %d", service.createUserCalls)
	}
}

type fakeUserService struct {
	createUserResponse model.User
	loginResponse      userservice.LoginResult
	createUserErr      error
	loginErr           error
	createUserCalls    int
	loginCalls         int
	refreshCalls       int
	logoutCalls        int
	refreshToken       string
	logoutToken        string
}

func (f *fakeUserService) CreateUser(ec *appcontext.GinContext, request userservice.CreateUserInput) (model.User, error) {
	f.createUserCalls++
	if f.createUserErr != nil {
		return model.User{}, f.createUserErr
	}
	if f.createUserResponse == (model.User{}) {
		f.createUserResponse = model.User{Model: model.Model{ID: "00000000-0000-4000-8000-000000000001"}, FullName: request.FullName, Username: request.Username, Email: request.Email}
	}
	return f.createUserResponse, nil
}

func (f *fakeUserService) Login(ec *appcontext.GinContext, request userservice.LoginInput) (userservice.LoginResult, error) {
	f.loginCalls++
	if f.loginErr != nil {
		return userservice.LoginResult{}, f.loginErr
	}
	return f.loginResponse, nil
}

func (f *fakeUserService) Refresh(ec *appcontext.GinContext, request userservice.RefreshInput) (userservice.LoginResult, error) {
	f.refreshCalls++
	f.refreshToken = request.RefreshToken
	if f.loginResponse == (userservice.LoginResult{}) {
		f.loginResponse = testLoginResult()
	}
	return f.loginResponse, nil
}

func (f *fakeUserService) Logout(ec *appcontext.GinContext, request userservice.RefreshInput) error {
	f.logoutCalls++
	f.logoutToken = request.RefreshToken
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

func testLoginResult() userservice.LoginResult {
	return userservice.LoginResult{
		Token:                 "token",
		TokenExpiresAt:        time.Now().UTC().Add(time.Hour),
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		User: model.User{
			Model:    model.Model{ID: "00000000-0000-4000-8000-000000000001"},
			FullName: "Analyst User",
			Username: "analyst",
			Email:    "analyst@example.com",
		},
	}
}
