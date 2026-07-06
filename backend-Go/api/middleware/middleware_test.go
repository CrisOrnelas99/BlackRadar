package middleware

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
	"secureops/backend-go/api/security"
)

func init() {
	sql.Register("secureops_tx_test", transactionTrackingDriver{})
}

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

func TestGormMiddlewareCommitsSuccessfulRequestTransaction(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(RequestContext())
	router.Use(GormMiddleware(database))

	var requestDatabase *gorm.DB
	router.GET("/resource", func(ctx *gin.Context) {
		ec := appcontext.FromGinContext(ctx)
		requestDatabase = ec.Database()
		if requestDatabase == nil {
			t.Fatal("expected request transaction to be stored on GinContext")
		}
		if requestDatabase == database {
			t.Fatal("expected context database to be a request transaction, not the base database")
		}

		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/resource", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	assertTransactionStats(t, 1, 1, 0)
}

func TestGormMiddlewareRollsBackUnsuccessfulStatus(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(RequestContext())
	router.Use(GormMiddleware(database))
	router.POST("/resource", func(ctx *gin.Context) {
		ctx.Status(http.StatusBadRequest)
	})

	recorder := performRequest(router, http.MethodPost, "/resource", nil)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	assertTransactionStats(t, 1, 0, 1)
}

func TestGormMiddlewareRollsBackContextErrors(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(RequestContext())
	router.Use(GormMiddleware(database))
	router.POST("/resource", func(ctx *gin.Context) {
		_ = ctx.Error(errors.New("handler failed"))
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodPost, "/resource", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	assertTransactionStats(t, 1, 0, 1)
}

func TestGormMiddlewareRollsBackPanics(t *testing.T) {
	database, closeDatabase := newTransactionTestDatabase(t)
	defer closeDatabase()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(RequestContext())
	router.Use(GormMiddleware(database))
	router.POST("/resource", func(ctx *gin.Context) {
		panic("boom")
	})

	recorder := performRequest(router, http.MethodPost, "/resource", nil)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}

	assertTransactionStats(t, 1, 0, 1)
}

func TestGormMiddlewareRejectsMissingDatabase(t *testing.T) {
	router := gin.New()
	router.Use(RequestContext())
	router.Use(GormMiddleware(nil))
	router.GET("/resource", func(ctx *gin.Context) {
		t.Fatal("handler should not run when database is missing")
	})

	recorder := performRequest(router, http.MethodGet, "/resource", nil)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
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

func TestFixedWindowRateLimiterBlocksAfterLimit(t *testing.T) {
	current := time.Unix(0, 0)
	limiter := newFixedWindowRateLimiter(RateLimitRule{
		Name:   "auth",
		Limit:  2,
		Window: time.Minute,
	}, func() time.Time {
		return current
	})

	if allowed, _ := limiter.Allow("203.0.113.10"); !allowed {
		t.Fatal("expected first request to be allowed")
	}
	if allowed, _ := limiter.Allow("203.0.113.10"); !allowed {
		t.Fatal("expected second request to be allowed")
	}
	if allowed, retryAfter := limiter.Allow("203.0.113.10"); allowed || retryAfter <= 0 {
		t.Fatalf("expected third request to be blocked with retry-after, got allowed=%v retryAfter=%v", allowed, retryAfter)
	}

	current = current.Add(time.Minute)
	if allowed, _ := limiter.Allow("203.0.113.10"); !allowed {
		t.Fatal("expected requests to be allowed after the window resets")
	}
}

func TestAuthRateLimitMiddlewareReturns429(t *testing.T) {
	router := gin.New()
	router.Use(AuthRateLimit())
	router.GET("/resource", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	for i := 0; i < 10; i++ {
		recorder := performRequest(router, http.MethodGet, "/resource", nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected request %d to be allowed, got %d", i+1, recorder.Code)
		}
	}

	recorder := performRequest(router, http.MethodGet, "/resource", nil)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate-limited request to return %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}
}

func TestAIRateLimitMiddlewareReturns429(t *testing.T) {
	router := gin.New()
	router.Use(AIRateLimit())
	router.GET("/ai", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		recorder := performRequest(router, http.MethodGet, "/ai", nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected request %d to be allowed, got %d", i+1, recorder.Code)
		}
	}

	recorder := performRequest(router, http.MethodGet, "/ai", nil)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate-limited request to return %d, got %d", http.StatusTooManyRequests, recorder.Code)
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
	sessionLookup := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: "00000000-0000-4000-8000-000000000042"}}

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
			Model:          model.Model{ID: "00000000-0000-4000-8000-000000000042"},
			OrganizationID: "00000000-0000-4000-8000-000000000099",
			Username:       "analyst",
			Role:           model.RoleUser,
		},
	}
	token := mustGenerateToken(t, jwtManager, "analyst", "session-1")
	sessionLookup := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: "session-1", UserID: "00000000-0000-4000-8000-000000000042"}}

	router := gin.New()
	router.Use(RequestContext())
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

func (f *fakeRefreshSessionLookup) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
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

type transactionCounters struct {
	mu        sync.Mutex
	begins    int
	commits   int
	rollbacks int
}

var testTransactionCounters transactionCounters

func resetTransactionStats() {
	testTransactionCounters.mu.Lock()
	defer testTransactionCounters.mu.Unlock()

	testTransactionCounters.begins = 0
	testTransactionCounters.commits = 0
	testTransactionCounters.rollbacks = 0
}

func assertTransactionStats(t *testing.T, begins int, commits int, rollbacks int) {
	t.Helper()

	testTransactionCounters.mu.Lock()
	defer testTransactionCounters.mu.Unlock()

	if testTransactionCounters.begins != begins || testTransactionCounters.commits != commits || testTransactionCounters.rollbacks != rollbacks {
		t.Fatalf(
			"expected transaction stats begins=%d commits=%d rollbacks=%d, got begins=%d commits=%d rollbacks=%d",
			begins,
			commits,
			rollbacks,
			testTransactionCounters.begins,
			testTransactionCounters.commits,
			testTransactionCounters.rollbacks,
		)
	}
}

func newTransactionTestDatabase(t *testing.T) (*gorm.DB, func()) {
	t.Helper()
	resetTransactionStats()

	sqlDatabase, err := sql.Open("secureops_tx_test", "")
	if err != nil {
		t.Fatalf("failed to open transaction test database: %v", err)
	}

	database, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDatabase}), &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		_ = sqlDatabase.Close()
		t.Fatalf("failed to open gorm transaction test database: %v", err)
	}

	return database, func() {
		_ = sqlDatabase.Close()
	}
}

type transactionTrackingDriver struct{}

func (transactionTrackingDriver) Open(name string) (driver.Conn, error) {
	return transactionTrackingConn{}, nil
}

type transactionTrackingConn struct{}

func (transactionTrackingConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not implemented for transaction middleware tests")
}

func (transactionTrackingConn) Close() error {
	return nil
}

func (transactionTrackingConn) Begin() (driver.Tx, error) {
	return transactionTrackingConn{}.BeginTx(context.Background(), driver.TxOptions{})
}

func (transactionTrackingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	testTransactionCounters.mu.Lock()
	testTransactionCounters.begins++
	testTransactionCounters.mu.Unlock()

	return transactionTrackingTx{}, nil
}

type transactionTrackingTx struct{}

func (transactionTrackingTx) Commit() error {
	testTransactionCounters.mu.Lock()
	testTransactionCounters.commits++
	testTransactionCounters.mu.Unlock()

	return nil
}

func (transactionTrackingTx) Rollback() error {
	testTransactionCounters.mu.Lock()
	testTransactionCounters.rollbacks++
	testTransactionCounters.mu.Unlock()

	return nil
}
