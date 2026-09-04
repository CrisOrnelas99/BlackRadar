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

	commonjwt "blackradar/api/common/jwt"
	"blackradar/api/common/pagination"
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
		user: model.User{Model: model.Model{ID: testUserID}, FullName: "Analyst User", Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	ctx := newUserServiceContext(t)

	createdUser, err := svc.CreateUser(ctx, CreateUserInput{FullName: "Analyst User", Username: "analyst", Email: "analyst@example.com", Password: "Password1!"})
	if err != nil {
		t.Fatalf("expected CreateUser to succeed, got %v", err)
	}
	if createdUser.ID != testUserID || createdUser.Username != "analyst" || createdUser.Email != "analyst@example.com" {
		t.Fatalf("unexpected created user response: %#v", createdUser)
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

func TestUserServiceAdminAccountChanges(t *testing.T) {
	repo := &fakeUserRepository{user: model.User{Model: model.Model{ID: testUserIDSeven}, Role: model.RoleUser, AccountStatus: model.AccountStatusActive}, activeAdminCount: 2}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	svc.transactionRunner = testTransactionRunner{}
	ctx := newUserServiceContext(t)
	ctx.SetUserID(testUserID)
	ctx.SetUserRole(model.RoleMaster)

	if _, err := svc.ChangeUserStatus(ctx, testUserIDSeven, model.AccountStatusDeactivated); err != nil {
		t.Fatalf("expected status change to succeed, got %v", err)
	}
	if repo.updatedStatus != model.AccountStatusDeactivated {
		t.Fatalf("expected status %q, got %q", model.AccountStatusDeactivated, repo.updatedStatus)
	}

	if _, err := svc.ChangeUserRole(ctx, testUserIDSeven, model.RoleAdmin); err != nil {
		t.Fatalf("expected role change to succeed, got %v", err)
	}
	if repo.updatedRole != model.RoleAdmin {
		t.Fatalf("expected role %q, got %q", model.RoleAdmin, repo.updatedRole)
	}
}

func TestUserServiceRejectsProtectedAdministratorChanges(t *testing.T) {
	repo := &fakeUserRepository{user: model.User{Model: model.Model{ID: testUserIDSeven}, Role: model.RoleAdmin, AccountStatus: model.AccountStatusActive}, activeAdminCount: 1}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	svc.transactionRunner = testTransactionRunner{}
	ctx := newUserServiceContext(t)
	ctx.SetUserRole(model.RoleAdmin)

	if _, err := svc.ChangeUserRole(ctx, testUserIDSeven, model.RoleUser); !errors.Is(err, ErrProtectedAdminAccount) {
		t.Fatalf("expected administrator role protection, got %v", err)
	}
	if _, err := svc.ChangeUserStatus(ctx, testUserIDSeven, model.AccountStatusDeactivated); !errors.Is(err, ErrProtectedAdminAccount) {
		t.Fatalf("expected administrator status protection, got %v", err)
	}
}

func TestUserServiceRejectsAdministratorAccountChanges(t *testing.T) {
	repo := &fakeUserRepository{user: model.User{Model: model.Model{ID: testUserIDSeven}, Role: model.RoleAdmin, AccountStatus: model.AccountStatusActive}, activeAdminCount: 2}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	svc.transactionRunner = testTransactionRunner{}
	ctx := newUserServiceContext(t)
	ctx.SetUserID(testUserID)
	ctx.SetUserRole(model.RoleAdmin)

	if _, err := svc.ChangeUserRole(ctx, testUserIDSeven, model.RoleUser); !errors.Is(err, ErrProtectedAdminAccount) {
		t.Fatalf("expected administrator role change to be rejected, got %v", err)
	}
	if _, err := svc.ChangeUserStatus(ctx, testUserIDSeven, model.AccountStatusDeactivated); !errors.Is(err, ErrProtectedAdminAccount) {
		t.Fatalf("expected administrator status change to be rejected, got %v", err)
	}
}

func TestSystemAdminCanChangeAnotherAdministrator(t *testing.T) {
	repo := &fakeUserRepository{user: model.User{Model: model.Model{ID: testUserIDSeven}, Role: model.RoleAdmin, AccountStatus: model.AccountStatusActive}, activeAdminCount: 2}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	svc.transactionRunner = testTransactionRunner{}
	ctx := newUserServiceContext(t)
	ctx.SetUserID(model.SystemAdminID)
	ctx.SetUserRole(model.RoleMaster)

	if _, err := svc.ChangeUserRole(ctx, testUserIDSeven, model.RoleUser); err != nil {
		t.Fatalf("expected system admin role change to succeed, got %v", err)
	}
	if _, err := svc.ChangeUserStatus(ctx, testUserIDSeven, model.AccountStatusDeactivated); err != nil {
		t.Fatalf("expected system admin status change to succeed, got %v", err)
	}
}

func TestUserServiceRejectsSelfAccountChanges(t *testing.T) {
	repo := &fakeUserRepository{user: model.User{Model: model.Model{ID: testUserID}, Role: model.RoleUser, AccountStatus: model.AccountStatusActive}, activeAdminCount: 2}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	svc.transactionRunner = testTransactionRunner{}
	ctx := newUserServiceContext(t)
	ctx.SetUserID(testUserID)
	ctx.SetUserRole(model.RoleAdmin)

	if _, err := svc.ChangeUserRole(ctx, testUserID, model.RoleAdmin); !errors.Is(err, ErrProtectedAdminAccount) {
		t.Fatalf("expected self role change to be rejected, got %v", err)
	}
	if _, err := svc.ChangeUserStatus(ctx, testUserID, model.AccountStatusDeactivated); !errors.Is(err, ErrProtectedAdminAccount) {
		t.Fatalf("expected self status change to be rejected, got %v", err)
	}
}

// TestUserServiceSupport verifies user service support behavior.
func TestUserServiceSupport(t *testing.T) {
	normalized := normalizeCreateUserInput(CreateUserInput{
		FullName: " Analyst User ",
		Username: " analyst ",
		Email:    " ANALYST@EXAMPLE.COM ",
		Password: " Password1! ",
	})
	if normalized.FullName != "Analyst User" || normalized.Username != "analyst" || normalized.Email != "analyst@example.com" || normalized.Password != "Password1!" {
		t.Fatalf("unexpected normalized request: %#v", normalized)
	}
	if err := validateCreateUserInput(normalized); err != nil {
		t.Fatalf("expected valid create user request, got %v", err)
	}
	if err := validateCreateUserInput(CreateUserInput{Username: "ab", Email: "bad", Password: "short"}); !errors.Is(err, ErrInvalidCreateUserRequest) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
	if err := validateCreateUserInput(CreateUserInput{Username: "analyst", Email: "Analyst <analyst@example.com>", Password: "Password1!"}); !errors.Is(err, ErrInvalidCreateUserRequest) {
		t.Fatalf("expected display-name email to be rejected, got %v", err)
	}
}

func TestUserServiceUpdateProfileNormalizesAndUpdatesAuthenticatedUser(t *testing.T) {
	repo := &fakeUserRepository{user: model.User{Model: model.Model{ID: testUserID}, FullName: "Old Name", Username: "analyst", Email: "old@example.com"}}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})

	updated, err := svc.UpdateProfile(newUserServiceContext(t), UpdateProfileInput{
		FullName: " New Name ",
		Username: " analyst2 ",
		Email:    " NEW@EXAMPLE.COM ",
	})
	if err != nil {
		t.Fatalf("expected profile update to succeed, got %v", err)
	}
	if updated.FullName != "New Name" || updated.Username != "analyst2" || updated.Email != "new@example.com" {
		t.Fatalf("unexpected updated profile: %#v", updated)
	}
}

// TestUserServiceValidationAndTranslation verifies validation and error mapping.
func TestUserServiceValidationAndTranslation(t *testing.T) {
	ctx := newUserServiceContext(t)
	svc := NewUserService(newTestJWTManager(t), &fakeUserRepository{findErr: userrepo.ErrRecordNotFound}, &fakeRefreshSessionRepository{})

	if _, err := svc.CreateUser(ctx, CreateUserInput{Username: "ab", Email: "bad", Password: "short"}); !errors.Is(err, ErrInvalidCreateUserRequest) {
		t.Fatalf("expected invalid request data, got %v", err)
	}
	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "missing", Password: "Password1!"}); !errors.Is(err, ErrInvalidLoginCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestUserServiceLoginStoresAndResetsAccountBackoff(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	svc.loginBackoff = newLoginBackoffTracker(func() time.Time { return now })
	ctx := newUserServiceContext(t)
	ctx.Request.RemoteAddr = "203.0.113.11:12345"

	for attempt := 0; attempt < loginBackoffFreeFailures+1; attempt++ {
		if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "WrongPassword1!"}); !errors.Is(err, ErrInvalidLoginCredentials) {
			t.Fatalf("expected invalid credentials on failure %d, got %v", attempt+1, err)
		}
	}
	if repo.user.FailedLoginCount != loginBackoffFreeFailures+1 || repo.user.LockedUntil == nil {
		t.Fatalf("expected account backoff state to be stored, got %#v", repo.user)
	}

	now = now.Add(time.Minute)
	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"}); err != nil {
		t.Fatalf("expected successful login after cooldown, got %v", err)
	}
	if repo.user.FailedLoginCount != 0 || repo.user.LastFailedLoginAt != nil || repo.user.LockedUntil != nil {
		t.Fatalf("expected successful login to clear account backoff state, got %#v", repo.user)
	}
}

func TestUserServiceErrorsExposeCategories(t *testing.T) {
	var validationErr *ValidationError
	if !errors.As(ErrInvalidCreateUserRequest, &validationErr) {
		t.Fatal("expected invalid create user request to be a user validation error")
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

// TestUserServiceCreateUserChecksEmailBeforeCreate verifies duplicate email validation runs before creation.
func TestUserServiceCreateUserChecksEmailBeforeCreate(t *testing.T) {
	users := &fakeUserRepository{emailExists: true}
	svc := NewUserService(newTestJWTManager(t), users, &fakeRefreshSessionRepository{})
	ctx := newUserServiceContext(t)

	_, err := svc.CreateUser(ctx, CreateUserInput{
		FullName: "Analyst User",
		Username: "analyst",
		Email:    "analyst@example.com",
		Password: "Password1!",
	})
	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("expected duplicate email conflict, got %v", err)
	}
	if users.createCalled {
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

// TestUserServiceRefreshRevokesAllSessionsOnReuse verifies token reuse contains the whole session family.
func TestUserServiceRefreshRevokesAllSessionsOnReuse(t *testing.T) {
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

	sessions.revoked = true

	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: login.RefreshToken}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected reused refresh token to be rejected, got %v", err)
	}
	if !sessions.revokeAllCalled {
		t.Fatal("expected refresh token reuse to revoke all active sessions for the user")
	}
}

// TestUserServiceLoginTranslatesSessionCreateFailure verifies login maps session persistence failures.
func TestUserServiceLoginTranslatesSessionCreateFailure(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	sessions := &fakeRefreshSessionRepository{createErr: userrepo.ErrPersistenceFailure}
	svc := NewUserService(newTestJWTManager(t), repo, sessions)
	ctx := newUserServiceContext(t)

	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"}); !errors.Is(err, ErrUserDependency) {
		t.Fatalf("expected dependency service error for session create failure, got %v", err)
	}
}

func TestUserServiceMissingJWTManagerReturnsInternalError(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewUserService(nil, repo, &fakeRefreshSessionRepository{})
	ctx := newUserServiceContext(t)

	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"}); !errors.Is(err, ErrUserInternal) {
		t.Fatalf("expected login without jwt manager to return internal error, got %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: "refresh"}); !errors.Is(err, ErrUserInternal) {
		t.Fatalf("expected refresh without jwt manager to return internal error, got %v", err)
	}
	if err := svc.Logout(ctx, RefreshInput{RefreshToken: "refresh"}); !errors.Is(err, ErrUserInternal) {
		t.Fatalf("expected logout without jwt manager to return internal error, got %v", err)
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

func TestUserServiceLoginBackoffUsesFibonacciCooldowns(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	repo := &fakeUserRepository{
		user: model.User{Model: model.Model{ID: testUserID}, Username: "analyst", Email: "analyst@example.com", PasswordHash: string(hash), Role: model.RoleUser},
	}
	svc := NewUserService(newTestJWTManager(t), repo, &fakeRefreshSessionRepository{})
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	svc.loginBackoff = newLoginBackoffTracker(func() time.Time { return now })
	ctx := newUserServiceContext(t)
	ctx.Request.RemoteAddr = "203.0.113.10:12345"

	wrongPassword := LoginInput{UserOrEmail: "analyst", Password: "WrongPassword1!"}

	for attempt := 1; attempt <= 4; attempt++ {
		if _, err := svc.Login(ctx, wrongPassword); !errors.Is(err, ErrInvalidLoginCredentials) {
			t.Fatalf("expected invalid credentials on failure %d, got %v", attempt, err)
		}
	}

	usernameCallsAfterFailure := repo.usernameLookupCalls

	if _, err := svc.Login(ctx, wrongPassword); err == nil {
		t.Fatal("expected backoff error after repeated failures")
	} else {
		if !errors.Is(err, ErrLoginBackoff) {
			t.Fatalf("expected login backoff sentinel, got %v", err)
		}
	}
	if repo.usernameLookupCalls != usernameCallsAfterFailure {
		t.Fatal("expected blocked login to stop before repository lookup")
	}

	now = now.Add(time.Minute)
	if _, err := svc.Login(ctx, LoginInput{UserOrEmail: "analyst", Password: "Password1!"}); err != nil {
		t.Fatalf("expected successful login to clear backoff, got %v", err)
	}
	usernameCallsAfterSuccess := repo.usernameLookupCalls

	if _, err := svc.Login(ctx, wrongPassword); !errors.Is(err, ErrInvalidLoginCredentials) {
		t.Fatalf("expected backoff to reset after success, got %v", err)
	}
	if repo.usernameLookupCalls != usernameCallsAfterSuccess+1 {
		t.Fatal("expected failed login after success to reach repository again")
	}
}

type fakeUserRepository struct {
	user                 model.User
	findErr              error
	exists               bool
	usernameExists       bool
	emailExists          bool
	usernameExistsOther  bool
	emailExistsOther     bool
	usernameLookupCalled bool
	emailLookupCalled    bool
	usernameLookupCalls  int
	emailLookupCalls     int
	createCalled         bool
	updateBackoffErr     error
	users                []model.User
	activeAdminCount     int64
	updatedRole          string
	updatedStatus        string
}

type testTransactionRunner struct{}

func (testTransactionRunner) Run(ec *appcontext.GinContext, operation func(*appcontext.GinContext) error) error {
	return operation(ec)
}

func (f *fakeUserRepository) ListUsers(ec *appcontext.GinContext, query model.UserListQuery) (pagination.Page[model.User], error) {
	return pagination.Page[model.User]{Items: f.users, Page: query.Pagination.Page, PageSize: query.Pagination.PageSize, TotalCount: int64(len(f.users))}, nil
}
func (f *fakeUserRepository) UpdateRole(ec *appcontext.GinContext, userID string, role string, updatedByID string) (model.User, error) {
	f.updatedRole = role
	f.user.Role = role
	return f.user, nil
}
func (f *fakeUserRepository) UpdateAccountStatus(ec *appcontext.GinContext, userID string, status string, updatedByID string) (model.User, error) {
	f.updatedStatus = status
	f.user.AccountStatus = status
	return f.user, nil
}
func (f *fakeUserRepository) CountActiveAdmins(ec *appcontext.GinContext) (int64, error) {
	return f.activeAdminCount, nil
}

// ExistsByUsername reports whether the fake user exists.
func (f *fakeUserRepository) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	if f.usernameExists {
		return true, nil
	}
	return f.exists, nil
}

// ExistsByUsernameExceptID reports whether another fake user uses username.
func (f *fakeUserRepository) ExistsByUsernameExceptID(ec *appcontext.GinContext, username string, userID string) (bool, error) {
	return f.usernameExistsOther, nil
}

// ExistsByEmail reports whether the fake user exists.
func (f *fakeUserRepository) ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error) {
	if f.emailExists {
		return true, nil
	}
	return f.exists, nil
}

// ExistsByEmailExceptID reports whether another fake user uses email.
func (f *fakeUserRepository) ExistsByEmailExceptID(ec *appcontext.GinContext, email string, userID string) (bool, error) {
	return f.emailExistsOther, nil
}

// CreateUser accepts the fake user without error.
func (f *fakeUserRepository) CreateUser(ec *appcontext.GinContext, user model.User) (model.User, error) {
	f.createCalled = true
	if user.ID == "" {
		user.ID = f.user.ID
	}
	f.user = user
	return user, nil
}

// UpdateProfile updates the fake user's mutable profile fields.
func (f *fakeUserRepository) UpdateProfile(ec *appcontext.GinContext, userID string, user model.User) (model.User, error) {
	if f.user.ID != userID {
		return model.User{}, userrepo.ErrRecordNotFound
	}
	f.user.FullName = user.FullName
	f.user.Username = user.Username
	f.user.Email = user.Email
	return f.user, nil
}

// FindByUsername returns the configured fake user.
func (f *fakeUserRepository) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	f.usernameLookupCalled = true
	f.usernameLookupCalls++
	return f.user, f.findErr
}

// FindByID returns the configured fake user by immutable identifier.
func (f *fakeUserRepository) FindByID(ec *appcontext.GinContext, id string) (model.User, error) {
	if f.findErr != nil {
		return model.User{}, f.findErr
	}
	if f.user.ID == "" || f.user.ID != id {
		return model.User{}, userrepo.ErrRecordNotFound
	}
	return f.user, nil
}

func (f *fakeUserRepository) FindByIDForManagement(ec *appcontext.GinContext, id string) (model.User, error) {
	if f.findErr != nil {
		return model.User{}, f.findErr
	}
	if f.user.ID == "" || f.user.ID != id {
		return model.User{}, userrepo.ErrRecordNotFound
	}
	return f.user, nil
}

// FindByEmail returns the configured fake user.
func (f *fakeUserRepository) FindByEmail(ec *appcontext.GinContext, email string) (model.User, error) {
	f.emailLookupCalled = true
	f.emailLookupCalls++
	return f.user, f.findErr
}

// UpdateLoginBackoff updates the fake account login state.
func (f *fakeUserRepository) UpdateLoginBackoff(ec *appcontext.GinContext, userID string, failedCount int, lastFailedAt, lockedUntil *time.Time) error {
	if f.updateBackoffErr != nil {
		return f.updateBackoffErr
	}
	f.user.FailedLoginCount = failedCount
	f.user.LastFailedLoginAt = lastFailedAt
	f.user.LockedUntil = lockedUntil
	return nil
}

var _ userrepo.UserRepositoryInterface = (*fakeUserRepository)(nil)

type fakeRefreshSessionRepository struct {
	session         model.RefreshSession
	revoked         bool
	revokeAllCalled bool
	createErr       error
	findErr         error
	revokeErr       error
}

// CreateRefreshSession stores the fake refresh session.
func (f *fakeRefreshSessionRepository) CreateRefreshSession(ec *appcontext.GinContext, session model.RefreshSession) error {
	if f.createErr != nil {
		return f.createErr
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

// RevokeActiveSessionsForUser revokes every fake active refresh session for the user.
func (f *fakeRefreshSessionRepository) RevokeActiveSessionsForUser(ec *appcontext.GinContext, userID string) error {
	f.revokeAllCalled = true
	if f.revokeErr != nil {
		return f.revokeErr
	}
	if f.session.TokenID != "" && f.session.UserID == userID {
		f.revoked = true
	}
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
	if err := ec.SetPrincipal(appcontext.Principal{UserID: testUserID, Username: "analyst", Role: model.RoleUser}); err != nil {
		t.Fatalf("failed to set test principal: %v", err)
	}
	return ec
}
