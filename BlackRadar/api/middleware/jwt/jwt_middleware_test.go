package jwtmiddleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
	appcontext "blackradar/api/requestContext"
	sharedjwt "blackradar/api/shared/jwt"
)

func TestJWTAuthenticationFilterRejectsInvalidRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtManager := sharedjwt.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")
	sessionLookup := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: "00000000-0000-4000-8000-000000000042"}}

	tests := []struct {
		name       string
		header     string
		headerFunc func(*testing.T) string
		lookup     *fakeUserLookup
	}{
		{name: "missing bearer token", lookup: &fakeUserLookup{}},
		{name: "invalid token", header: "Bearer invalid-token", lookup: &fakeUserLookup{}},
		{
			name: "unknown user",
			headerFunc: func(t *testing.T) string {
				return "Bearer " + mustGenerateToken(t, jwtManager, "analyst", "session-1")
			},
			lookup: &fakeUserLookup{exists: false},
		},
		{
			name: "lookup error",
			headerFunc: func(t *testing.T) string {
				return "Bearer " + mustGenerateToken(t, jwtManager, "analyst", "session-1")
			},
			lookup: &fakeUserLookup{exists: true, existsErr: errors.New("lookup failed")},
		},
		{
			name: "find user error",
			headerFunc: func(t *testing.T) string {
				return "Bearer " + mustGenerateToken(t, jwtManager, "analyst", "session-1")
			},
			lookup: &fakeUserLookup{exists: true, findErr: errors.New("find failed")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := tt.header
			if tt.headerFunc != nil {
				header = tt.headerFunc(t)
			}

			router := gin.New()
			router.Use(JWTAuthenticationFilter(jwtManager, tt.lookup, sessionLookup))
			router.GET("/private", func(ctx *gin.Context) {
				t.Fatal("handler should not run for invalid authentication")
			})

			recorder := performRequest(router, http.MethodGet, "/private", func(request *http.Request) {
				if header != "" {
					request.Header.Set("Authorization", header)
				}
			})

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
			}
			if recorder.Body.String() != `{"error":"Unauthorized"}` {
				t.Fatalf("unexpected response body: %q", recorder.Body.String())
			}
		})
	}
}

func TestJWTAuthenticationFilterSetsAuthenticatedUserContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtManager := sharedjwt.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")
	lookup := &fakeUserLookup{
		exists: true,
		user: model.User{
			Model:          model.Model{ID: "00000000-0000-4000-8000-000000000042"},
			OrganizationID: "00000000-0000-4000-8000-000000000099",
			Username:       "analyst",
			Role:           model.RoleUser,
		},
	}
	token := mustGenerateToken(t, jwtManager, "analyst", "session-1")
	sessionLookup := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: "00000000-0000-4000-8000-000000000042"}}

	router := gin.New()
	router.Use(contextmiddleware.RequestContext())
	router.Use(JWTAuthenticationFilter(jwtManager, lookup, sessionLookup))
	router.GET("/private", func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)
		if ec.Username() != "analyst" {
			t.Fatalf("expected username analyst, got %v", ec.Username())
		}
		if ec.UserID() != "00000000-0000-4000-8000-000000000042" {
			t.Fatalf("expected user ID 42, got %v", ec.UserID())
		}
		if ec.UserRole() != model.RoleUser {
			t.Fatalf("expected user role %s, got %v", model.RoleUser, ec.UserRole())
		}
		if ec.OrganizationID() != "00000000-0000-4000-8000-000000000099" {
			t.Fatalf("expected organization ID 99, got %v", ec.OrganizationID())
		}
		if lookup.existsContext == nil || lookup.findContext == nil {
			t.Fatal("expected user lookup to receive GinContext")
		}
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/private", func(request *http.Request) {
		request.Header.Set("Authorization", "Bearer "+token)
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestJWTAuthenticationEntryPoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/private", JWTAuthenticationEntryPoint)

	recorder := performRequest(router, http.MethodGet, "/private", nil)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
	if recorder.Body.String() != `{"error":"Unauthorized"}` {
		t.Fatalf("unexpected response body: %q", recorder.Body.String())
	}
}

type fakeUserLookup struct {
	exists        bool
	existsErr     error
	findErr       error
	user          model.User
	existsContext *appcontext.GinContext
	findContext   *appcontext.GinContext
}

func (f *fakeUserLookup) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	f.existsContext = ec
	return f.exists, f.existsErr
}

func (f *fakeUserLookup) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	f.findContext = ec
	return f.user, f.findErr
}

type fakeRefreshSessionLookup struct {
	session model.RefreshSession
}

func (f *fakeRefreshSessionLookup) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
	if f.session.TokenID == tokenID && f.session.UserID == userID {
		return f.session, nil
	}
	return model.RefreshSession{}, baserepository.ErrRefreshSessionNotFound
}

func mustGenerateToken(t *testing.T, jwtManager *sharedjwt.JWTManager, username string, tokenID string) string {
	t.Helper()
	token, err := jwtManager.GenerateToken(username, tokenID)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
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
