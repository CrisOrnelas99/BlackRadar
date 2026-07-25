// Package service verifies user service behavior.
package service

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	commonjwt "blackradar/api/common/jwt"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	userrepo "blackradar/api/repository/user"
)

const (
	testUserID         = "00000000-0000-4000-8000-000000000001"
	testUserIDSeven    = "00000000-0000-4000-8000-000000000007"
	testUserIDFortyTwo = "00000000-0000-4000-8000-000000000042"
	testJWTSecret      = "0123456789abcdef0123456789abcdef"
)

// TestUserService verifies the happy-path user service flow.
func TestUserService(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	ctx := newUserServiceContext(t)

	registerResponse, err := svc.Register(ctx, RegisterInput{Username: "analyst", Email: "analyst@example.com", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Register to succeed, got %v", err)
	}
	if registerResponse.ID != testUserID || registerResponse.Username != "analyst" || registerResponse.Email != "analyst@example.com" {
		t.Fatalf("unexpected register response: %#v", registerResponse)
	}

	loginResponse, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}
	if loginResponse.Token == "" || loginResponse.RefreshToken == "" {
		t.Fatal("expected access and refresh tokens to be populated")
	}
	if loginResponse.TokenExpiresAt.IsZero() || loginResponse.RefreshTokenExpiresAt.IsZero() {
		t.Fatal("expected token expirations to be populated")
	}
	if !loginResponse.RefreshTokenExpiresAt.After(loginResponse.TokenExpiresAt) {
		t.Fatalf("expected refresh token expiry to outlast access token expiry")
	}
}

// TestUserServiceHelpers verifies user helper behavior.
func TestUserServiceHelpers(t *testing.T) {
	normalized := normalizeRegisterInput(RegisterInput{
		Username: " analyst ",
		Email:    " ANALYST@EXAMPLE.COM ",
		Password: " Password1! ",
	})
	if normalized.Username != "analyst" || normalized.Email != "analyst@example.com" || normalized.Password != "Password1!" {
		t.Fatalf("unexpected normalized request: %#v", normalized)
	}
	if err := validateRegisterInput(normalized); err != nil {
		t.Fatalf("expected valid register request, got %v", err)
	}
	if err := validateRegisterInput(RegisterInput{Username: "ab", Email: "bad", Password: "short"}); !errors.Is(err, ErrInvalidRegisterRequest) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
}

// TestUserServiceValidationAndTranslation verifies validation and error mapping.
func TestUserServiceValidationAndTranslation(t *testing.T) {
	ctx := newUserServiceContext(t)
	svc := NewUserService(newTestJWTManager(t), &fakeUserRepository{findErr: gorm.ErrRecordNotFound}, &fakeRefreshSessionRepository{})

	if _, err := svc.Register(ctx, RegisterInput{Username: "ab", Email: "bad", Password: "short"}); !errors.Is(err, ErrInvalidRegisterRequest) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "missing", Password: "Password1!"}); !errors.Is(err, ErrInvalidLoginCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestUserServiceErrorsExposeCategories(t *testing.T) {
	var validationErr *ValidationError
	if !errors.As(ErrInvalidRegisterRequest, &validationErr) {
		t.Fatal("expected invalid register request to be a user validation error")
	}
	var conflictErr *ConflictError
	if !errors.As(ErrUsernameAlreadyExists, &conflictErr) {
		t.Fatal("expected duplicate username to be a user conflict error")
	}
	var unauthorizedErr *UnauthorizedError
	if !errors.As(ErrInvalidLoginCredentials, &unauthorizedErr) {
		t.Fatal("expected invalid login credentials to be a user unauthorized error")
	}
	var dependencyErr *DependencyError
	if !errors.As(ErrUserDependency, &dependencyErr) {
		t.Fatal("expected user dependency failure to be a user dependency error")
	}
	var internalErr *InternalError
	if !errors.As(ErrUserInternal, &internalErr) {
		t.Fatal("expected user internal failure to be a user internal error")
	}
}

// TestUserServiceRegisterChecksEmailBeforeSave verifies duplicate email validation runs before persistence.
func TestUserServiceRegisterChecksEmailBeforeSave(t *testing.T) {
	users := &fakeUserRepository{emailExists: true}
	svc := NewUserService(newTestJWTManager(t), users, &fakeRefreshSessionRepository{})
	ctx := newUserServiceContext(t)

	_, err := svc.Register(ctx, RegisterInput{
		Username: "analyst",
		Email:    "analyst@example.com",
		Password: "Password1!",
	})
	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("expected duplicate email conflict, got %v", err)
	}
	if users.saveCalled {
		t.Fatal("expected duplicate email to be rejected before saving user")
	}
}

// TestUserServiceLogoutRejectsSecondLogout verifies refresh sessions cannot be reused after logout.
func TestUserServiceLogoutRejectsSecondLogout(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserIDSeven}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{}
	svc := NewUserService(newTestJWTManager(t), repo, sessions)
	ctx := newUserServiceContext(t)

	login, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}

	if err := svc.Logout(ctx, RefreshInput{RefreshToken: login.RefreshToken}); err != nil {
		t.Fatalf("expected first Logout to succeed, got %v", err)
	}

	if err := svc.Logout(ctx, RefreshInput{RefreshToken: login.RefreshToken}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected second Logout to be rejected, got %v", err)
	}
}

// TestUserServiceRefreshTranslatesSessionLookupFailure verifies refresh lookup failures map to dependencies.
func TestUserServiceRefreshTranslatesSessionLookupFailure(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{}
	svc := NewUserService(newTestJWTManager(t), repo, sessions)
	ctx := newUserServiceContext(t)

	login, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}

	sessions.findErr = userrepo.ErrPersistenceFailure

	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: login.RefreshToken}); !errors.Is(err, ErrUserDependency) {
		t.Fatalf("expected dependency service error for session lookup failure, got %v", err)
	}
}

// TestUserServiceLoginTranslatesSessionSaveFailure verifies login maps session persistence failures.
func TestUserServiceLoginTranslatesSessionSaveFailure(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{saveErr: userrepo.ErrPersistenceFailure}
	svc := NewUserService(newTestJWTManager(t), repo, sessions)
	ctx := newUserServiceContext(t)

	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"}); !errors.Is(err, ErrUserDependency) {
		t.Fatalf("expected dependency service error for session save failure, got %v", err)
	}
}

// TestUserServiceLoginResolvesUsernameAndEmailDeterministically verifies username/email lookup selection.
func TestUserServiceLoginResolvesUsernameAndEmailDeterministically(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserIDFortyTwo}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	ctx := newUserServiceContext(t)

	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"}); err != nil {
		t.Fatalf("expected username login to succeed, got %v", err)
	}
	if !repo.usernameLookupCalled {
		t.Fatal("expected username lookup to be used")
	}

	repo.usernameLookupCalled = false
	repo.emailLookupCalled = false

	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst@example.com", Password: "Password1!"}); err != nil {
		t.Fatalf("expected email login to succeed, got %v", err)
	}
	if !repo.emailLookupCalled {
		t.Fatal("expected email lookup to be used")
	}
}

type fakeUserRepository struct {
	user                 model.User
	findErr              error
	exists               bool
	usernameExists       bool
	emailExists          bool
	usernameLookupCalled bool
	emailLookupCalled    bool
	saveCalled           bool
}

// ExistsByUsername reports whether the fake user exists.
func (f *fakeUserRepository) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	if f.usernameExists {
		return true, nil
	}
	return f.exists, nil
}

// ExistsByEmail reports whether the fake user exists.
func (f *fakeUserRepository) ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error) {
	if f.emailExists {
		return true, nil
	}
	return f.exists, nil
}

// Save accepts the fake user without error.
func (f *fakeUserRepository) Save(ec *appcontext.GinContext, user model.User) (model.User, error) {
	f.saveCalled = true
	if user.ID == "" {
		user.ID = f.user.ID
	}
	f.user = user
	return user, nil
}

// FindByUsernameOrEmail returns the configured fake user.
func (f *fakeUserRepository) FindByUsernameOrEmail(ec *appcontext.GinContext, userOrEmail string) (model.User, error) {
	return f.user, f.findErr
}

// FindByUsername returns the configured fake user.
func (f *fakeUserRepository) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	f.usernameLookupCalled = true
	return f.user, f.findErr
}

// FindByID returns the configured fake user by immutable identifier.
func (f *fakeUserRepository) FindByID(ec *appcontext.GinContext, id string) (model.User, error) {
	if f.findErr != nil {
		return model.User{}, f.findErr
	}
	if f.user.ID == "" || f.user.ID != id {
		return model.User{}, gorm.ErrRecordNotFound
	}
	return f.user, nil
}

// FindByEmail returns the configured fake user.
func (f *fakeUserRepository) FindByEmail(ec *appcontext.GinContext, email string) (model.User, error) {
	f.emailLookupCalled = true
	return f.user, f.findErr
}

var _ userrepo.UserRepositoryInterface = (*fakeUserRepository)(nil)

type fakeRefreshSessionRepository struct {
	session   model.RefreshSession
	revoked   bool
	saveErr   error
	findErr   error
	revokeErr error
}

// Save stores the fake refresh session.
func (f *fakeRefreshSessionRepository) Save(ec *appcontext.GinContext, session model.RefreshSession) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.session = session
	return nil
}

// FindActiveByTokenIDForUser returns the active fake refresh session.
func (f *fakeRefreshSessionRepository) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
	if f.findErr != nil {
		return model.RefreshSession{}, f.findErr
	}
	if f.session.TokenID == "" || f.revoked || f.session.TokenID != tokenID || f.session.UserID != userID {
		return model.RefreshSession{}, userrepo.ErrRecordNotFound
	}
	return f.session, nil
}

// RevokeByTokenIDForUser revokes the fake refresh session.
func (f *fakeRefreshSessionRepository) RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	if f.session.TokenID == "" || f.revoked || f.session.TokenID != tokenID || f.session.UserID != userID {
		return userrepo.ErrRecordNotFound
	}
	f.revoked = true
	return nil
}

var _ userrepo.RefreshSessionRepositoryInterface = (*fakeRefreshSessionRepository)(nil)

func newTestJWTManager(t *testing.T) *commonjwt.Manager {
	t.Helper()

	jwtManager, err := commonjwt.NewManager(testJWTSecret, time.Hour, time.Hour*24, "issuer", "audience")
	if err != nil {
		t.Fatalf("failed to create jwt manager: %v", err)
	}

	return jwtManager
}

// newUserServiceContext creates a request context for user service tests.
func newUserServiceContext(t *testing.T) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	appcontext.SetGinContext(ctx, ec)
	return ec
}
