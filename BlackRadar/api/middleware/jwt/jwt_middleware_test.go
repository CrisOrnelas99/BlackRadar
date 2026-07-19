package jwtmiddleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	commonjwt "blackradar/api/common/jwt"
	contextmiddleware "blackradar/api/middleware/context"
	"blackradar/api/model"
	requestcontext "blackradar/api/platform/requestcontext"
	userrepository "blackradar/api/repository/user"
)

const testJWTSecret = "0123456789abcdef0123456789abcdef"

func TestAuthenticationRejectsMissingDependencies(t *testing.T) {
	jwtManager := newTestJWTManager(t)
	users := &fakeUserLookup{}
	sessions := &fakeRefreshSessionLookup{}

	tests := []struct {
		name       string
		manager    *commonjwt.Manager
		users      UserLookup
		sessions   RefreshSessionLookup
		expectedIs error
	}{
		{name: "missing manager", users: users, sessions: sessions, expectedIs: ErrJWTManagerRequired},
		{name: "missing users", manager: jwtManager, sessions: sessions, expectedIs: ErrJWTUserLookupRequired},
		{name: "missing sessions", manager: jwtManager, users: users, expectedIs: ErrJWTSessionLookupRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := Authentication(tt.manager, tt.users, tt.sessions)

			if middleware != nil {
				t.Fatal("expected middleware to be nil")
			}
			if !errors.Is(err, tt.expectedIs) {
				t.Fatalf("expected %v, got %v", tt.expectedIs, err)
			}
		})
	}
}

func TestBearerTokenParsesStrictAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		expected   string
		shouldPass bool
	}{
		{name: "standard bearer", header: "Bearer token-1", expected: "token-1", shouldPass: true},
		{name: "case insensitive bearer", header: "bearer token-1", expected: "token-1", shouldPass: true},
		{name: "extra whitespace", header: "Bearer   token-1", expected: "token-1", shouldPass: true},
		{name: "missing token", header: "Bearer ", shouldPass: false},
		{name: "wrong scheme", header: "Basic token-1", shouldPass: false},
		{name: "extra fields", header: "Bearer token-1 extra", shouldPass: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, ok := bearerToken(tt.header)

			if ok != tt.shouldPass {
				t.Fatalf("expected ok=%v, got %v", tt.shouldPass, ok)
			}
			if token != tt.expected {
				t.Fatalf("expected token %q, got %q", tt.expected, token)
			}
		})
	}
}

func TestAuthenticationRejectsInvalidCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtManager := newTestJWTManager(t)
	userID := "00000000-0000-4000-8000-000000000042"
	sessionID := "session-1"
	user := model.User{
		Model:    model.Model{ID: userID},
		Username: "analyst",
		Role:     model.RoleUser,
	}
	activeSession := model.RefreshSession{TokenID: sessionID, UserID: userID}

	tests := []struct {
		name     string
		header   string
		users    *fakeUserLookup
		sessions *fakeRefreshSessionLookup
	}{
		{name: "missing bearer token", users: &fakeUserLookup{user: user}, sessions: &fakeRefreshSessionLookup{session: activeSession}},
		{name: "invalid token", header: "Bearer invalid-token", users: &fakeUserLookup{user: user}, sessions: &fakeRefreshSessionLookup{session: activeSession}},
		{
			name:     "unknown user",
			header:   "Bearer " + mustGenerateToken(t, jwtManager, userID, "analyst", sessionID),
			users:    &fakeUserLookup{findErr: gorm.ErrRecordNotFound},
			sessions: &fakeRefreshSessionLookup{session: activeSession},
		},
		{
			name:     "user identity mismatch",
			header:   "Bearer " + mustGenerateToken(t, jwtManager, userID, "analyst", sessionID),
			users:    &fakeUserLookup{user: model.User{Model: model.Model{ID: "00000000-0000-4000-8000-000000000043"}}},
			sessions: &fakeRefreshSessionLookup{session: activeSession},
		},
		{
			name:     "inactive session",
			header:   "Bearer " + mustGenerateToken(t, jwtManager, userID, "analyst", sessionID),
			users:    &fakeUserLookup{user: user},
			sessions: &fakeRefreshSessionLookup{findErr: userrepository.ErrRefreshSessionNotFound},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := performAuthenticatedRequest(t, jwtManager, tt.users, tt.sessions, tt.header)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
			}
			if recorder.Body.String() != `{"error":"Unauthorized"}` {
				t.Fatalf("unexpected response body: %q", recorder.Body.String())
			}
			if recorder.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("expected WWW-Authenticate Bearer header")
			}
		})
	}
}

func TestAuthenticationReturnsServiceUnavailableForLookupFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtManager := newTestJWTManager(t)
	userID := "00000000-0000-4000-8000-000000000042"
	sessionID := "session-1"
	user := model.User{
		Model:    model.Model{ID: userID},
		Username: "analyst",
		Role:     model.RoleUser,
	}
	token := "Bearer " + mustGenerateToken(t, jwtManager, userID, "analyst", sessionID)

	tests := []struct {
		name     string
		users    *fakeUserLookup
		sessions *fakeRefreshSessionLookup
	}{
		{
			name:     "user lookup failure",
			users:    &fakeUserLookup{findErr: errors.New("database unavailable")},
			sessions: &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: sessionID, UserID: userID}},
		},
		{
			name:     "session lookup failure",
			users:    &fakeUserLookup{user: user},
			sessions: &fakeRefreshSessionLookup{findErr: errors.New("database unavailable")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := performAuthenticatedRequest(t, jwtManager, tt.users, tt.sessions, token)

			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, recorder.Code)
			}
			if recorder.Body.String() != `{"error":"database unavailable"}` {
				t.Fatalf("unexpected response body: %q", recorder.Body.String())
			}
		})
	}
}

func TestAuthenticationReturnsInternalErrorForContextAndPrincipalFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtManager := newTestJWTManager(t)
	userID := "00000000-0000-4000-8000-000000000042"
	sessionID := "session-1"
	token := "Bearer " + mustGenerateToken(t, jwtManager, userID, "analyst", sessionID)

	t.Run("missing request context", func(t *testing.T) {
		router := gin.New()
		router.Use(mustAuthentication(t, jwtManager, &fakeUserLookup{}, &fakeRefreshSessionLookup{}))
		router.GET("/private", func(ctx *gin.Context) {
			t.Fatal("handler should not run")
		})

		recorder := performRequest(router, http.MethodGet, "/private", func(request *http.Request) {
			request.Header.Set("Authorization", token)
		})

		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
		}
	})

}

func TestAuthenticationSetsAuthenticatedUserContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtManager := newTestJWTManager(t)
	userID := "00000000-0000-4000-8000-000000000042"
	sessionID := "session-1"
	lookup := &fakeUserLookup{
		user: model.User{
			Model:    model.Model{ID: userID},
			Username: "analyst",
			Role:     model.RoleUser,
		},
	}
	sessionLookup := &fakeRefreshSessionLookup{session: model.RefreshSession{TokenID: sessionID, UserID: userID}}
	token := mustGenerateToken(t, jwtManager, userID, "analyst", sessionID)

	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil))
	router.Use(mustAuthentication(t, jwtManager, lookup, sessionLookup))
	router.GET("/private", func(ctx *gin.Context) {
		ec, err := requestcontext.FromGinContext(ctx)
		if err != nil {
			t.Fatalf("expected request context, got %v", err)
		}
		username, err := ec.Username()
		if err != nil || username != "analyst" {
			t.Fatalf("expected username analyst, got %v error=%v", username, err)
		}
		userID, err := ec.UserID()
		if err != nil || userID != "00000000-0000-4000-8000-000000000042" {
			t.Fatalf("expected user ID 42, got %v error=%v", userID, err)
		}
		role, err := ec.UserRole()
		if err != nil || role != model.RoleUser {
			t.Fatalf("expected user role %s, got %v error=%v", model.RoleUser, role, err)
		}
		if lookup.findContext == nil {
			t.Fatal("expected user lookup to receive GinContext")
		}
		ctx.Status(http.StatusOK)
	})

	recorder := performRequest(router, http.MethodGet, "/private", func(request *http.Request) {
		request.Header.Set("Authorization", "bearer   "+token)
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func performAuthenticatedRequest(
	t *testing.T,
	jwtManager *commonjwt.Manager,
	users UserLookup,
	sessions RefreshSessionLookup,
	header string,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.Use(contextmiddleware.RequestContext(nil))
	router.Use(mustAuthentication(t, jwtManager, users, sessions))
	router.GET("/private", func(ctx *gin.Context) {
		t.Fatal("handler should not run")
	})

	return performRequest(router, http.MethodGet, "/private", func(request *http.Request) {
		if header != "" {
			request.Header.Set("Authorization", header)
		}
	})
}

func mustAuthentication(
	t *testing.T,
	jwtManager *commonjwt.Manager,
	users UserLookup,
	sessions RefreshSessionLookup,
) gin.HandlerFunc {
	t.Helper()

	middleware, err := Authentication(jwtManager, users, sessions)
	if err != nil {
		t.Fatalf("failed to create authentication middleware: %v", err)
	}

	return middleware
}

type fakeUserLookup struct {
	findErr     error
	user        model.User
	findContext *requestcontext.GinContext
}

func (f *fakeUserLookup) FindByID(ec *requestcontext.GinContext, id string) (model.User, error) {
	f.findContext = ec
	return f.user, f.findErr
}

type fakeRefreshSessionLookup struct {
	findErr error
	session model.RefreshSession
}

func (f *fakeRefreshSessionLookup) FindActiveByTokenIDForUser(ec *requestcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
	if f.findErr != nil {
		return model.RefreshSession{}, f.findErr
	}
	if f.session.TokenID == tokenID && f.session.UserID == userID {
		return f.session, nil
	}
	return model.RefreshSession{}, userrepository.ErrRefreshSessionNotFound
}

func newTestJWTManager(t *testing.T) *commonjwt.Manager {
	t.Helper()

	jwtManager, err := commonjwt.NewManager(testJWTSecret, time.Hour, time.Hour*24, "issuer", "audience")
	if err != nil {
		t.Fatalf("failed to create jwt manager: %v", err)
	}

	return jwtManager
}

func mustGenerateToken(t *testing.T, jwtManager *commonjwt.Manager, userID string, username string, tokenID string) string {
	t.Helper()
	token, err := jwtManager.GenerateAccessToken(userID, username, tokenID)
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
