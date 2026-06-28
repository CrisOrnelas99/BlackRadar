// Package service verifies authentication service behavior.
package service

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
	"secureops/backend-go/api/security"
	baseservice "secureops/backend-go/api/service"
)

// TestAuthService verifies the happy-path authentication service flow.
func TestAuthService(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{ID: 1, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewAuthService(security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience"), repo, &fakeRefreshSessionRepository{})
	ctx := newAuthServiceContext(t)

	if err := svc.Register(ctx, dto.RegisterRequest{Username: "analyst", Email: "analyst@example.com", Password: "Password1!"}); err != nil {
		t.Fatalf("expected Register to succeed, got %v", err)
	}
	response, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}
	if response.Token == "" {
		t.Fatal("expected token to be populated")
	}
	if response.RefreshToken == "" {
		t.Fatal("expected refresh token to be populated")
	}
}

// TestAuthServiceHelpers verifies authentication helper behavior.
func TestAuthServiceHelpers(t *testing.T) {
	normalized := baseservice.NormalizeRegisterRequest(dto.RegisterRequest{
		Username: " analyst ",
		Email:    " ANALYST@EXAMPLE.COM ",
		Password: " Password1! ",
	})
	if normalized.Username != "analyst" || normalized.Email != "analyst@example.com" || normalized.Password != "Password1!" {
		t.Fatalf("unexpected normalized request: %#v", normalized)
	}
	if err := baseservice.ValidateRegisterRequest(normalized); err != nil {
		t.Fatalf("expected valid register request, got %v", err)
	}
	if err := baseservice.ValidateRegisterRequest(dto.RegisterRequest{Username: "ab", Email: "bad", Password: "short"}); !errors.Is(err, baseservice.ErrInvalidRequestData) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
}

// TestAuthServiceValidationAndTranslation verifies validation and error mapping.
func TestAuthServiceValidationAndTranslation(t *testing.T) {
	ctx := newAuthServiceContext(t)
	svc := NewAuthService(security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience"), &fakeUserRepository{findErr: gorm.ErrRecordNotFound}, &fakeRefreshSessionRepository{})

	if err := svc.Register(ctx, dto.RegisterRequest{Username: "ab", Email: "bad", Password: "short"}); !errors.Is(err, baseservice.ErrInvalidRequestData) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
	if _, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "missing", Password: "Password1!"}); !errors.Is(err, baseservice.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestAuthServiceLogoutRejectsSecondLogout(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{ID: 7, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{}
	svc := NewAuthService(security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience"), repo, sessions)
	ctx := newAuthServiceContext(t)

	login, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}

	if err := svc.Logout(ctx, dto.RefreshRequest{RefreshToken: login.RefreshToken}); err != nil {
		t.Fatalf("expected first Logout to succeed, got %v", err)
	}

	if err := svc.Logout(ctx, dto.RefreshRequest{RefreshToken: login.RefreshToken}); !errors.Is(err, baseservice.ErrInvalidCredentials) {
		t.Fatalf("expected second Logout to be rejected, got %v", err)
	}
}

func TestAuthServiceLoginResolvesUsernameAndEmailDeterministically(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{ID: 42, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewAuthService(security.NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience"), repo, &fakeRefreshSessionRepository{})
	ctx := newAuthServiceContext(t)

	if _, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst", Password: "Password1!"}); err != nil {
		t.Fatalf("expected username login to succeed, got %v", err)
	}
	if !repo.usernameLookupCalled {
		t.Fatal("expected username lookup to be used")
	}

	repo.usernameLookupCalled = false
	repo.emailLookupCalled = false

	if _, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst@example.com", Password: "Password1!"}); err != nil {
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
	usernameLookupCalled bool
	emailLookupCalled    bool
}

// ExistsByUsername reports whether the fake user exists.
func (f *fakeUserRepository) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	return f.exists, nil
}

// ExistsByEmail reports whether the fake user exists.
func (f *fakeUserRepository) ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error) {
	return f.exists, nil
}

// Save accepts the fake user without error.
func (f *fakeUserRepository) Save(ec *appcontext.GinContext, user model.User) error { return nil }

// FindByUsernameOrEmail returns the configured fake user.
func (f *fakeUserRepository) FindByUsernameOrEmail(ec *appcontext.GinContext, userOrEmail string) (model.User, error) {
	return f.user, f.findErr
}

// FindByUsername returns the configured fake user.
func (f *fakeUserRepository) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	f.usernameLookupCalled = true
	return f.user, f.findErr
}

// FindByEmail returns the configured fake user.
func (f *fakeUserRepository) FindByEmail(ec *appcontext.GinContext, email string) (model.User, error) {
	f.emailLookupCalled = true
	return f.user, f.findErr
}

var _ baserepository.UserRepository = (*fakeUserRepository)(nil)

type fakeRefreshSessionRepository struct {
	session model.RefreshSession
	revoked bool
}

func (f *fakeRefreshSessionRepository) Save(ec *appcontext.GinContext, session model.RefreshSession) error {
	f.session = session
	return nil
}

func (f *fakeRefreshSessionRepository) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID int64) (model.RefreshSession, error) {
	if f.session.TokenID == "" || f.revoked || f.session.TokenID != tokenID || f.session.UserID != userID {
		return model.RefreshSession{}, baserepository.ErrRefreshSessionNotFound
	}
	return f.session, nil
}

func (f *fakeRefreshSessionRepository) RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID int64) error {
	if f.session.TokenID == "" || f.revoked || f.session.TokenID != tokenID || f.session.UserID != userID {
		return baserepository.ErrRefreshSessionNotFound
	}
	f.revoked = true
	return nil
}

var _ baserepository.RefreshSessionRepository = (*fakeRefreshSessionRepository)(nil)

// newAuthServiceContext creates a request context for auth service tests.
func newAuthServiceContext(t *testing.T) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", log.New(io.Discard, "", 0))
	appcontext.SetGinContext(ctx, ec)
	return ec
}
