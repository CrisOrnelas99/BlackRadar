package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
	"secureops/backend-go/api/security"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func TestRequestContextStoresGinContextAndContinues(t *testing.T) {
	router := gin.New()
	router.Use(RequestContext())
	router.GET("/resource", func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)

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

	recorder := performRequest(router, http.MethodGet, "/resource", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestGormMiddlewareStoresDatabaseOnGinContext(t *testing.T) {
	database := &gorm.DB{}
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		appcontext.SetGinContext(ctx, appcontext.NewGinContext(ctx, "txn-123", nil))
		ctx.Next()
	})
	router.Use(GormMiddleware(database))
	router.GET("/resource", func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)
		if ec.Database() != database {
			t.Fatal("expected database to be stored on GinContext")
		}

		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/resource", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestRequestFilterAllowsNormalRequests(t *testing.T) {
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
		{
			name:     "path traversal",
			target:   "/assets",
			rawQuery: "file=../secret",
		},
		{
			name:     "encoded script tag",
			target:   "/assets",
			rawQuery: "q=%3Cscript%3Ealert(1)%3C/script%3E",
		},
		{
			name:     "sql injection",
			target:   "/assets",
			rawQuery: "q=' or 1=1",
		},
		{
			name:     "drop table",
			target:   "/assets",
			rawQuery: "q=drop table users",
		},
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

func TestRequireAdmin(t *testing.T) {
	tests := []struct {
		name           string
		role           any
		expectStatus   int
		expectContinue bool
	}{
		{
			name:         "missing role",
			expectStatus: http.StatusForbidden,
		},
		{
			name:         "wrong type",
			role:         42,
			expectStatus: http.StatusForbidden,
		},
		{
			name:         "normal user",
			role:         model.RoleUser,
			expectStatus: http.StatusForbidden,
		},
		{
			name:           "admin",
			role:           model.RoleAdmin,
			expectStatus:   http.StatusOK,
			expectContinue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			if tt.role != nil {
				router.Use(func(ctx *gin.Context) {
					ec := appcontext.FromGinContext(ctx)
					if role, ok := tt.role.(string); ok {
						ec.SetUserRole(role)
					} else {
						ctx.Set("userRole", tt.role)
					}
					ctx.Next()
				})
			}
			router.Use(RequireAdmin())

			handlerCalled := false
			router.GET("/admin", func(ctx *gin.Context) {
				handlerCalled = true
				ctx.Status(http.StatusOK)
			})

			recorder := performRequest(router, http.MethodGet, "/admin", nil)

			if recorder.Code != tt.expectStatus {
				t.Fatalf("expected status %d, got %d", tt.expectStatus, recorder.Code)
			}
			if handlerCalled != tt.expectContinue {
				t.Fatalf("expected handler called=%v, got %v", tt.expectContinue, handlerCalled)
			}
		})
	}
}

func TestJWTAuthenticationFilterRejectsInvalidRequests(t *testing.T) {
	jwtManager := security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")
	sessionLookup := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: 42}}

	tests := []struct {
		name       string
		header     string
		headerFunc func(*testing.T) string
		lookup     *fakeUserLookup
	}{
		{
			name:   "missing bearer token",
			lookup: &fakeUserLookup{},
		},
		{
			name:   "invalid token",
			header: "Bearer invalid-token",
			lookup: &fakeUserLookup{},
		},
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
	jwtManager := security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")
	lookup := &fakeUserLookup{
		exists: true,
		user: model.User{
			ID:       42,
			Username: "analyst",
			Role:     model.RoleUser,
		},
	}
	token := mustGenerateToken(t, jwtManager, "analyst", "session-1")
	sessionLookup := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: 42}}

	router := gin.New()
	router.Use(RequestContext())
	router.Use(JWTAuthenticationFilter(jwtManager, lookup, sessionLookup))
	router.GET("/private", func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)
		if ec.Username() != "analyst" {
			t.Fatalf("expected username analyst, got %v", ec.Username())
		}
		if ec.UserID() != int64(42) {
			t.Fatalf("expected user ID 42, got %v", ec.UserID())
		}
		if ec.UserRole() != model.RoleUser {
			t.Fatalf("expected user role %s, got %v", model.RoleUser, ec.UserRole())
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

func TestSecurityHeaders(t *testing.T) {
	router := gin.New()
	router.Use(SecurityHeaders())
	router.GET("/resource", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/resource", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	expectedHeaders := map[string]string{
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
	}

	for header, expected := range expectedHeaders {
		if actual := recorder.Header().Get(header); actual != expected {
			t.Fatalf("expected %s header %q, got %q", header, expected, actual)
		}
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

func mustGenerateToken(t *testing.T, jwtManager *security.JWTManager, username string, tokenID string) string {
	t.Helper()

	token, err := jwtManager.GenerateToken(username, tokenID)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	return token
}

type fakeRefreshSessionLookup struct {
	session model.RefreshSession
}

func (f *fakeRefreshSessionLookup) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID int64) (model.RefreshSession, error) {
	if f.session.TokenID == tokenID && f.session.UserID == userID {
		return f.session, nil
	}
	return model.RefreshSession{}, baserepository.ErrRefreshSessionNotFound
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
