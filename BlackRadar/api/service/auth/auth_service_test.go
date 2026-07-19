// Package service verifies authentication service behavior.
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
	"blackradar/api/controller/dto"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	baserepository "blackradar/api/repository"
	userrepo "blackradar/api/repository/user"
	baseservice "blackradar/api/service"
)

const (
	testUserID         = "00000000-0000-4000-8000-000000000001"
	testUserIDSeven    = "00000000-0000-4000-8000-000000000007"
	testUserIDFortyTwo = "00000000-0000-4000-8000-000000000042"
	testOrgID          = "00000000-0000-4000-8000-000000000011"
	testJWTSecret      = "0123456789abcdef0123456789abcdef"
)

// TestAuthService verifies the happy-path authentication service flow.
func TestAuthService(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, OrganizationID: testOrgID, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewAuthService(newTestJWTManager(t), &fakeOrganizationRepository{organization: model.Organization{Model: model.Model{ID: testOrgID}, Name: "home"}}, repo, &fakeRefreshSessionRepository{})
	ctx := newAuthServiceContext(t)

	registerResponse, err := svc.Register(ctx, dto.RegisterRequest{Username: "analyst", Email: "analyst@example.com", Organization: "home", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Register to succeed, got %v", err)
	}
	if registerResponse.ID != testUserID || registerResponse.Username != "analyst" || registerResponse.Email != "analyst@example.com" {
		t.Fatalf("unexpected register response: %#v", registerResponse)
	}
	if registerResponse.Organization != "home" {
		t.Fatalf("expected register response organization home, got %#v", registerResponse)
	}
	loginResponse, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}
	if loginResponse.Token == "" {
		t.Fatal("expected token to be populated")
	}
	if loginResponse.RefreshToken == "" {
		t.Fatal("expected refresh token to be populated")
	}
	if loginResponse.TokenExpiresAt.IsZero() {
		t.Fatal("expected token expiration to be populated")
	}
	if loginResponse.RefreshTokenExpiresAt.IsZero() {
		t.Fatal("expected refresh token expiration to be populated")
	}
	if !loginResponse.RefreshTokenExpiresAt.After(loginResponse.TokenExpiresAt) {
		t.Fatalf("expected refresh token expiry to outlast access token expiry, got access=%v refresh=%v", loginResponse.TokenExpiresAt, loginResponse.RefreshTokenExpiresAt)
	}
	if loginResponse.User.Organization != "home" {
		t.Fatalf("expected login response organization home, got %#v", loginResponse.User)
	}
}

// TestAuthServiceHelpers verifies authentication helper behavior.
func TestAuthServiceHelpers(t *testing.T) {
	normalized := baseservice.NormalizeRegisterRequest(dto.RegisterRequest{
		Username:     " analyst ",
		Email:        " ANALYST@EXAMPLE.COM ",
		Organization: " home ",
		Password:     " Password1! ",
	})
	if normalized.Username != "analyst" || normalized.Email != "analyst@example.com" || normalized.Organization != "home" || normalized.Password != "Password1!" {
		t.Fatalf("unexpected normalized request: %#v", normalized)
	}
	if err := baseservice.ValidateRegisterRequest(normalized); err != nil {
		t.Fatalf("expected valid register request, got %v", err)
	}
	if err := baseservice.ValidateRegisterRequest(dto.RegisterRequest{Username: "ab", Email: "bad", Organization: "home", Password: "short"}); !errors.Is(err, baseservice.ErrInvalidRequestData) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
}

// TestAuthServiceValidationAndTranslation verifies validation and error mapping.
func TestAuthServiceValidationAndTranslation(t *testing.T) {
	ctx := newAuthServiceContext(t)
	svc := NewAuthService(newTestJWTManager(t), &fakeOrganizationRepository{findErr: gorm.ErrRecordNotFound}, &fakeUserRepository{findErr: gorm.ErrRecordNotFound}, &fakeRefreshSessionRepository{})

	if _, err := svc.Register(ctx, dto.RegisterRequest{Username: "ab", Email: "bad", Organization: "home", Password: "short"}); !errors.Is(err, ErrInvalidRegisterRequest) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
	if _, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "missing", Password: "Password1!"}); !errors.Is(err, ErrInvalidLoginCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestAuthServiceRegisterChecksEmailBeforeCreatingOrganization(t *testing.T) {
	organizations := &fakeOrganizationRepository{findErr: gorm.ErrRecordNotFound}
	users := &fakeUserRepository{emailExists: true}
	svc := NewAuthService(newTestJWTManager(t), organizations, users, &fakeRefreshSessionRepository{})
	ctx := newAuthServiceContext(t)

	_, err := svc.Register(ctx, dto.RegisterRequest{
		Username:     "analyst",
		Email:        "analyst@example.com",
		Organization: "home",
		Password:     "Password1!",
	})
	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("expected duplicate email conflict, got %v", err)
	}
	if organizations.saveCalled {
		t.Fatal("expected duplicate email to be rejected before creating organization")
	}
}

func TestAuthServiceLogoutRejectsSecondLogout(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserIDSeven}, OrganizationID: testOrgID, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{}
	svc := NewAuthService(newTestJWTManager(t), &fakeOrganizationRepository{organization: model.Organization{Model: model.Model{ID: testOrgID}, Name: "home"}}, repo, sessions)
	ctx := newAuthServiceContext(t)

	login, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}

	if err := svc.Logout(ctx, dto.RefreshRequest{RefreshToken: login.RefreshToken}); err != nil {
		t.Fatalf("expected first Logout to succeed, got %v", err)
	}

	if err := svc.Logout(ctx, dto.RefreshRequest{RefreshToken: login.RefreshToken}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected second Logout to be rejected, got %v", err)
	}
}

func TestAuthServiceRefreshTranslatesSessionLookupFailure(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, OrganizationID: testOrgID, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{}
	svc := NewAuthService(newTestJWTManager(t), &fakeOrganizationRepository{organization: model.Organization{Model: model.Model{ID: testOrgID}, Name: "home"}}, repo, sessions)
	ctx := newAuthServiceContext(t)

	login, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected Login to succeed, got %v", err)
	}

	sessions.findErr = userrepo.ErrPersistenceFailure

	if _, err := svc.Refresh(ctx, dto.RefreshRequest{RefreshToken: login.RefreshToken}); !errors.Is(err, baseservice.ErrInternal) {
		t.Fatalf("expected internal service error for session lookup failure, got %v", err)
	}
}

func TestAuthServiceLoginTranslatesSessionSaveFailure(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, OrganizationID: testOrgID, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{saveErr: userrepo.ErrPersistenceFailure}
	svc := NewAuthService(newTestJWTManager(t), &fakeOrganizationRepository{organization: model.Organization{Model: model.Model{ID: testOrgID}, Name: "home"}}, repo, sessions)
	ctx := newAuthServiceContext(t)

	if _, err := svc.Login(ctx, dto.LoginRequest{UserOrEmail: "analyst", Password: "Password1!"}); !errors.Is(err, baseservice.ErrInternal) {
		t.Fatalf("expected internal service error for session save failure, got %v", err)
	}
}

func TestAuthServiceLoginResolvesUsernameAndEmailDeterministically(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserIDFortyTwo}, OrganizationID: testOrgID, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewAuthService(newTestJWTManager(t), &fakeOrganizationRepository{organization: model.Organization{Model: model.Model{ID: testOrgID}, Name: "home"}}, repo, &fakeRefreshSessionRepository{})
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
	usernameExists       bool
	emailExists          bool
	usernameLookupCalled bool
	emailLookupCalled    bool
}

type fakeOrganizationRepository struct {
	organization model.Organization
	findErr      error
	saveCalled   bool
}

// FindByID returns the configured fake organization.
func (f *fakeOrganizationRepository) FindByID(ec *appcontext.GinContext, id string) (model.Organization, error) {
	if f.findErr != nil {
		return model.Organization{}, f.findErr
	}
	if f.organization.ID == "" || f.organization.ID != id {
		return model.Organization{}, gorm.ErrRecordNotFound
	}
	return f.organization, nil
}

func (f *fakeOrganizationRepository) FindByName(ec *appcontext.GinContext, name string) (model.Organization, error) {
	if f.findErr != nil {
		return model.Organization{}, f.findErr
	}
	if f.organization.Name == "" {
		return model.Organization{}, gorm.ErrRecordNotFound
	}
	return f.organization, nil
}

func (f *fakeOrganizationRepository) Save(ec *appcontext.GinContext, organization model.Organization) (model.Organization, error) {
	f.saveCalled = true
	if organization.ID == "" {
		organization.ID = f.organization.ID
	}
	f.organization = organization
	return organization, nil
}

var _ baserepository.OrganizationRepository = (*fakeOrganizationRepository)(nil)

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

var _ baserepository.UserRepository = (*fakeUserRepository)(nil)

type fakeRefreshSessionRepository struct {
	session   model.RefreshSession
	revoked   bool
	saveErr   error
	findErr   error
	revokeErr error
}

func (f *fakeRefreshSessionRepository) Save(ec *appcontext.GinContext, session model.RefreshSession) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.session = session
	return nil
}

func (f *fakeRefreshSessionRepository) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
	if f.findErr != nil {
		return model.RefreshSession{}, f.findErr
	}
	if f.session.TokenID == "" || f.revoked || f.session.TokenID != tokenID || f.session.UserID != userID {
		return model.RefreshSession{}, userrepo.ErrRefreshSessionNotFound
	}
	return f.session, nil
}

func (f *fakeRefreshSessionRepository) RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	if f.session.TokenID == "" || f.revoked || f.session.TokenID != tokenID || f.session.UserID != userID {
		return userrepo.ErrRefreshSessionNotFound
	}
	f.revoked = true
	return nil
}

var _ baserepository.RefreshSessionRepository = (*fakeRefreshSessionRepository)(nil)

func newTestJWTManager(t *testing.T) *commonjwt.Manager {
	t.Helper()

	jwtManager, err := commonjwt.NewManager(testJWTSecret, time.Hour, time.Hour*24, "issuer", "audience")
	if err != nil {
		t.Fatalf("failed to create jwt manager: %v", err)
	}

	return jwtManager
}

// newAuthServiceContext creates a request context for auth service tests.
func newAuthServiceContext(t *testing.T) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ec := appcontext.NewGinContext(ctx, "txn-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
	appcontext.SetGinContext(ctx, ec)
	return ec
}
