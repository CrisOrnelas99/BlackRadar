// Package service provides user application services.
package service

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	commonjwt "blackradar/api/common/jwt"
	"blackradar/api/common/pagination"
	commontoken "blackradar/api/common/token"
	"blackradar/api/model"
	"blackradar/api/platform/config"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	transactionboundary "blackradar/api/platform/transaction"
	userrepository "blackradar/api/repository/user"
	auditservice "blackradar/api/service/audit"
)

// CreateUserInput contains the fields required to provision a user account.
type CreateUserInput struct {
	FullName string
	Username string
	Email    string
	Password string
}

// UpdateProfileInput contains mutable profile fields for the authenticated user.
type UpdateProfileInput struct {
	FullName string
	Username string
	Email    string
}

// LoginInput contains the credentials used to authenticate a user.
type LoginInput struct {
	UserOrEmail string
	Password    string
}

// RefreshInput contains the refresh token used for token rotation or logout.
type RefreshInput struct {
	RefreshToken string
}

// LoginResult contains issued credentials and the authenticated user.
type LoginResult struct {
	User                  model.User
	Token                 string
	TokenExpiresAt        time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

// userServiceImpl implements user authentication workflows.
type userServiceImpl struct {
	jwtManager               *commonjwt.Manager
	userRepository           userrepository.UserRepositoryInterface
	refreshSessionRepository userrepository.RefreshSessionRepositoryInterface
	transactionRunner        transactionboundary.Runner
	auditService             auditservice.Service
	loginBackoff             *loginBackoffTracker
}

const loginBackoffFreeFailures = 3

var loginBackoffSchedule = []time.Duration{
	time.Minute,
	2 * time.Minute,
	3 * time.Minute,
	5 * time.Minute,
	8 * time.Minute,
}

type loginBackoffTracker struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]loginBackoffEntry
}

type loginBackoffEntry struct {
	failures     int
	blockedUntil time.Time
}

// newLoginBackoffTracker creates the in-memory login backoff tracker.
func newLoginBackoffTracker(now func() time.Time) *loginBackoffTracker {
	if now == nil {
		now = time.Now
	}

	return &loginBackoffTracker{now: now, entries: make(map[string]loginBackoffEntry)}
}

// loginBackoffState returns the service login backoff tracker.
func (s *userServiceImpl) loginBackoffState() *loginBackoffTracker {
	if s.loginBackoff == nil {
		s.loginBackoff = newLoginBackoffTracker(time.Now)
	}
	return s.loginBackoff
}

// loginBackoffKey builds the tracker key from the client IP and login identifier.
func loginBackoffKey(ec *appcontext.GinContext, normalizedUserOrEmail string) string {
	identifier := strings.TrimSpace(normalizedUserOrEmail)
	if identifier == "" {
		identifier = "unknown"
	}

	clientIP := "unknown"
	if ec != nil {
		clientIP = strings.TrimSpace(ec.ClientIP())
		if clientIP == "" {
			clientIP = "unknown"
		}
	}

	return clientIP + "|" + identifier
}

// Check reports whether the login key is still blocked.
func (tracker *loginBackoffTracker) Check(key string) (time.Duration, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := tracker.now()
	entry, exists := tracker.entries[key]
	if !exists || entry.blockedUntil.IsZero() {
		return 0, false
	}
	if now.Before(entry.blockedUntil) {
		return entry.blockedUntil.Sub(now), true
	}

	entry.blockedUntil = time.Time{}
	tracker.entries[key] = entry
	return 0, false
}

// RecordFailure stores a failed attempt and returns the active cooldown.
func (tracker *loginBackoffTracker) RecordFailure(key string) time.Duration {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := tracker.now()
	entry := tracker.entries[key]
	if !entry.blockedUntil.IsZero() && now.Before(entry.blockedUntil) {
		return entry.blockedUntil.Sub(now)
	}

	entry.failures++
	entry.blockedUntil = time.Time{}
	if entry.failures > loginBackoffFreeFailures {
		delay := loginBackoffDelay(entry.failures - loginBackoffFreeFailures - 1)
		entry.blockedUntil = now.Add(delay)
		tracker.entries[key] = entry
		return delay
	}

	tracker.entries[key] = entry
	return 0
}

// Reset clears the tracker state for a login key.
func (tracker *loginBackoffTracker) Reset(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	delete(tracker.entries, key)
}

// loginBackoffDelay returns the cooldown for a failure index.
func loginBackoffDelay(index int) time.Duration {
	if index < 0 {
		return 0
	}
	if index >= len(loginBackoffSchedule) {
		index = len(loginBackoffSchedule) - 1
	}
	return loginBackoffSchedule[index]
}

// NewUserService creates a user service backed by the supplied dependencies.
func NewUserService(jwtManager *commonjwt.Manager, userRepository userrepository.UserRepositoryInterface, refreshSessionRepository userrepository.RefreshSessionRepositoryInterface, auditServices ...auditservice.Service) *userServiceImpl {
	service := &userServiceImpl{
		jwtManager:               jwtManager,
		userRepository:           userRepository,
		refreshSessionRepository: refreshSessionRepository,
		transactionRunner:        platformdb.RequestTransactionRunner{},
		loginBackoff:             newLoginBackoffTracker(time.Now),
	}
	if len(auditServices) > 0 {
		service.auditService = auditServices[0]
	}
	return service
}

// ListUsers returns account records for administrator-only safe response mapping.
func (s *userServiceImpl) ListUsers(ec *appcontext.GinContext, query model.UserListQuery) (pagination.Page[model.User], error) {
	query, err := normalizeUserListQuery(query)
	if err != nil {
		return pagination.Page[model.User]{}, err
	}
	users, err := s.userRepository.ListUsers(ec, query.Pagination)
	if err != nil {
		return pagination.Page[model.User]{}, translateUserRepositoryError(err)
	}
	if totalPages := users.TotalPages(); totalPages > 0 && users.Page > totalPages {
		query.Pagination.Page = totalPages
		users, err = s.userRepository.ListUsers(ec, query.Pagination)
	}
	return users, nil
}

// GetUserForManagement returns one active or deactivated account for administrators.
func (s *userServiceImpl) GetUserForManagement(ec *appcontext.GinContext, userID string) (model.User, error) {
	user, err := s.userRepository.FindByIDForManagement(ec, userID)
	if err != nil {
		return model.User{}, translateUserManagementRepositoryError(err)
	}
	return user, nil
}

// CreateUser validates and provisions a standard user account.
func (s *userServiceImpl) CreateUser(ec *appcontext.GinContext, request CreateUserInput) (model.User, error) {
	request = normalizeCreateUserInput(request)
	if err := validateCreateUserInput(request); err != nil {
		return model.User{}, ErrInvalidCreateUserRequest
	}

	exists, err := s.userRepository.ExistsByUsername(ec, request.Username)
	if err != nil {
		return model.User{}, translateUserRepositoryError(err)
	}
	if exists {
		return model.User{}, ErrUsernameAlreadyExists
	}

	exists, err = s.userRepository.ExistsByEmail(ec, request.Email)
	if err != nil {
		return model.User{}, translateUserRepositoryError(err)
	}
	if exists {
		return model.User{}, ErrEmailAlreadyExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), config.PasswordCost())
	if err != nil {
		return model.User{}, fmt.Errorf("%w: hash password: %w", ErrUserInternal, err)
	}

	newUser := model.User{
		FullName:      request.FullName,
		Username:      request.Username,
		Email:         request.Email,
		Role:          model.RoleUser,
		AccountStatus: model.AccountStatusActive,
		PasswordHash:  string(hash),
	}
	user, err := s.userRepository.CreateUser(ec, newUser)
	if err != nil {
		return model.User{}, translateUserRepositoryError(err)
	}
	return user, nil
}

// ChangeUserRole updates an account role while preserving administrator invariants.
func (s *userServiceImpl) ChangeUserRole(ec *appcontext.GinContext, userID string, role string) (model.User, error) {
	actorID, err := ec.UserID()
	if err != nil || !validRole(role) {
		return model.User{}, ErrInvalidUserManagement
	}
	var updated model.User
	err = s.runUserManagementTransaction(ec, func(txContext *appcontext.GinContext) error {
		target, findErr := s.userRepository.FindByIDForManagement(txContext, userID)
		if findErr != nil {
			return translateUserManagementRepositoryError(findErr)
		}
		if target.ID == actorID || (target.Role == model.RoleAdmin && actorID != model.SystemAdminID) {
			return ErrProtectedAdminAccount
		}
		if target.Role == role {
			updated = target
			return nil
		}
		if target.Role == model.RoleAdmin && role != model.RoleAdmin {
			count, countErr := s.userRepository.CountActiveAdmins(txContext)
			if countErr != nil {
				return translateUserRepositoryError(countErr)
			}
			if count <= 1 {
				return ErrLastActiveAdmin
			}
		}
		var updateErr error
		updated, updateErr = s.userRepository.UpdateRole(txContext, userID, role, actorID)
		if updateErr != nil {
			return translateUserManagementRepositoryError(updateErr)
		}
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return updated, nil
}

// ChangeUserStatus activates or deactivates an account.
func (s *userServiceImpl) ChangeUserStatus(ec *appcontext.GinContext, userID string, status string) (model.User, error) {
	actorID, err := ec.UserID()
	if err != nil || !validAccountStatus(status) {
		return model.User{}, ErrInvalidUserManagement
	}
	var updated model.User
	err = s.runUserManagementTransaction(ec, func(txContext *appcontext.GinContext) error {
		target, findErr := s.userRepository.FindByIDForManagement(txContext, userID)
		if findErr != nil {
			return translateUserManagementRepositoryError(findErr)
		}
		if target.ID == actorID || (target.Role == model.RoleAdmin && actorID != model.SystemAdminID) {
			return ErrProtectedAdminAccount
		}
		if target.AccountStatus == status {
			updated = target
			return nil
		}
		if target.Role == model.RoleAdmin && target.AccountStatus == model.AccountStatusActive && status == model.AccountStatusDeactivated {
			count, countErr := s.userRepository.CountActiveAdmins(txContext)
			if countErr != nil {
				return translateUserRepositoryError(countErr)
			}
			if count <= 1 {
				return ErrLastActiveAdmin
			}
		}
		var updateErr error
		updated, updateErr = s.userRepository.UpdateAccountStatus(txContext, userID, status, actorID)
		if updateErr != nil {
			return translateUserManagementRepositoryError(updateErr)
		}
		if status == model.AccountStatusDeactivated {
			if revokeErr := s.refreshSessionRepository.RevokeActiveSessionsForUser(txContext, userID); revokeErr != nil {
				return translateUserRepositoryError(revokeErr)
			}
		}
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return updated, nil
}

// UpdateProfile validates and updates the authenticated user's profile.
func (s *userServiceImpl) UpdateProfile(ec *appcontext.GinContext, request UpdateProfileInput) (model.User, error) {
	userID, err := ec.UserID()
	if err != nil {
		return model.User{}, ErrInvalidProfileUpdate
	}

	request = normalizeProfileUpdateInput(request)
	if err := validateProfileUpdateInput(request); err != nil {
		return model.User{}, ErrInvalidProfileUpdate
	}

	exists, err := s.userRepository.ExistsByUsernameExceptID(ec, request.Username, userID)
	if err != nil {
		return model.User{}, translateUserRepositoryError(err)
	}
	if exists {
		return model.User{}, ErrUsernameAlreadyExists
	}

	exists, err = s.userRepository.ExistsByEmailExceptID(ec, request.Email, userID)
	if err != nil {
		return model.User{}, translateUserRepositoryError(err)
	}
	if exists {
		return model.User{}, ErrEmailAlreadyExists
	}

	user, err := s.userRepository.UpdateProfile(ec, userID, model.User{
		FullName: request.FullName,
		Username: request.Username,
		Email:    request.Email,
	})
	if err != nil {
		return model.User{}, translateUserRepositoryError(err)
	}

	return user, nil
}

// Login validates credentials and returns a signed access token.
func (s *userServiceImpl) Login(ec *appcontext.GinContext, request LoginInput) (LoginResult, error) {
	request.UserOrEmail = strings.TrimSpace(request.UserOrEmail)
	isEmailLogin := isEmailLikeLoginIdentifier(request.UserOrEmail)
	if isEmailLogin {
		request.UserOrEmail = strings.ToLower(request.UserOrEmail)
	}
	loginKey := loginBackoffKey(ec, request.UserOrEmail)
	loginBackoff := s.loginBackoffState()
	if _, blocked := loginBackoff.Check(loginKey); blocked {
		if err := s.recordAudit(ec, auditservice.EventInput{Action: "auth.login", ResourceType: "user", Result: auditservice.ResultDenied}); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrLoginBackoff
	}
	if request.UserOrEmail == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		if err := consumeLoginFailureWork(request.Password); err != nil {
			return LoginResult{}, err
		}
		s.loginBackoffState().RecordFailure(loginKey)
		if err := s.recordAudit(ec, auditservice.EventInput{Action: "auth.login", ResourceType: "user", Result: auditservice.ResultDenied}); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrInvalidLoginCredentials
	}

	var user model.User
	var err error
	if isEmailLogin {
		user, err = s.userRepository.FindByEmail(ec, request.UserOrEmail)
	} else {
		user, err = s.userRepository.FindByUsername(ec, request.UserOrEmail)
	}
	if err != nil {
		if errors.Is(err, userrepository.ErrRecordNotFound) {
			if timingErr := consumeLoginFailureWork(request.Password); timingErr != nil {
				return LoginResult{}, timingErr
			}
			s.loginBackoffState().RecordFailure(loginKey)
			if auditErr := s.recordAudit(ec, auditservice.EventInput{Action: "auth.login", ResourceType: "user", Result: auditservice.ResultDenied}); auditErr != nil {
				return LoginResult{}, auditErr
			}
			return LoginResult{}, ErrInvalidLoginCredentials
		}
		return LoginResult{}, translateUserRepositoryError(err)
	}

	now := loginBackoff.now().UTC()
	if user.LockedUntil != nil && now.Before(*user.LockedUntil) {
		if timingErr := consumeLoginFailureWork(request.Password); timingErr != nil {
			return LoginResult{}, timingErr
		}
		if auditErr := s.recordAudit(ec, auditservice.EventInput{Action: "auth.login", ResourceType: "user", Result: auditservice.ResultDenied}); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, ErrLoginBackoff
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		if timingErr := consumeLoginFailureWork(request.Password); timingErr != nil {
			return LoginResult{}, timingErr
		}
		user.FailedLoginCount++
		user.LastFailedLoginAt = &now
		var lockedUntil *time.Time
		if user.FailedLoginCount > loginBackoffFreeFailures {
			until := now.Add(loginBackoffDelay(user.FailedLoginCount - loginBackoffFreeFailures - 1))
			lockedUntil = &until
		}
		if updateErr := s.userRepository.UpdateLoginBackoff(ec, user.ID, user.FailedLoginCount, user.LastFailedLoginAt, lockedUntil); updateErr != nil {
			return LoginResult{}, translateUserRepositoryError(updateErr)
		}
		loginBackoff.RecordFailure(loginKey)
		if err := s.recordAudit(ec, auditservice.EventInput{Action: "auth.login", ResourceType: "user", Result: auditservice.ResultDenied}); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrInvalidLoginCredentials
	}

	if user.FailedLoginCount > 0 || user.LastFailedLoginAt != nil || user.LockedUntil != nil {
		if updateErr := s.userRepository.UpdateLoginBackoff(ec, user.ID, 0, nil, nil); updateErr != nil {
			return LoginResult{}, translateUserRepositoryError(updateErr)
		}
	}
	loginBackoff.Reset(loginKey)

	if s.jwtManager == nil {
		return LoginResult{}, fmt.Errorf("%w: missing jwt manager", ErrUserInternal)
	}

	refreshTokenID, err := commontoken.NewID()
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: create refresh session token ID: %w", ErrUserInternal, err)
	}
	now = time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	token, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, refreshTokenID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: generate access token: %w", ErrUserInternal, err)
	}
	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Username, refreshTokenID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: generate refresh token: %w", ErrUserInternal, err)
	}
	if err := s.createRefreshSession(ec, user.ID, refreshTokenID, refreshExpiresAt); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		User:                  user,
		Token:                 token,
		TokenExpiresAt:        accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// Refresh validates a refresh token and returns rotated credentials.
func (s *userServiceImpl) Refresh(ec *appcontext.GinContext, request RefreshInput) (LoginResult, error) {
	refreshToken := strings.TrimSpace(request.RefreshToken)
	if refreshToken == "" {
		if err := s.recordAudit(ec, auditservice.EventInput{Action: "auth.refresh", ResourceType: "refresh_session", Result: auditservice.ResultDenied}); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrInvalidRefreshToken
	}

	if s.jwtManager == nil {
		return LoginResult{}, fmt.Errorf("%w: missing jwt manager", ErrUserInternal)
	}

	claims, err := s.jwtManager.ExtractRefreshClaims(refreshToken)
	if err != nil {
		if auditErr := s.recordAudit(ec, auditservice.EventInput{Action: "auth.refresh", ResourceType: "refresh_session", Result: auditservice.ResultDenied}); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, ErrInvalidRefreshToken
	}

	user, err := s.userRepository.FindByID(ec, claims.Subject)
	if err != nil {
		if errors.Is(err, userrepository.ErrRecordNotFound) {
			if auditErr := s.recordAudit(ec, auditservice.EventInput{ActorUserID: &claims.Subject, Action: "auth.refresh.reuse", ResourceType: "refresh_session", Result: auditservice.ResultDenied}); auditErr != nil {
				return LoginResult{}, auditErr
			}
			return LoginResult{}, ErrInvalidRefreshToken
		}
		return LoginResult{}, translateUserRepositoryError(err)
	}

	session, err := s.refreshSessionRepository.FindActiveByTokenIDForUser(ec, claims.ID, user.ID)
	if err != nil {
		if errors.Is(err, userrepository.ErrRecordNotFound) {
			if revokeErr := s.revokeAllRefreshSessionsForUser(ec, user.ID); revokeErr != nil {
				return LoginResult{}, revokeErr
			}
			return LoginResult{}, ErrInvalidRefreshToken
		}
		return LoginResult{}, translateUserRepositoryError(err)
	}

	if session.UserID != user.ID {
		if err := s.revokeAllRefreshSessionsForUser(ec, user.ID); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrInvalidRefreshToken
	}

	newRefreshTokenID, err := commontoken.NewID()
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: create refresh session token ID: %w", ErrUserInternal, err)
	}
	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, newRefreshTokenID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: generate access token: %w", ErrUserInternal, err)
	}
	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Username, newRefreshTokenID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: generate refresh token: %w", ErrUserInternal, err)
	}
	if err := s.rotateRefreshSession(ec, session, newRefreshTokenID, refreshExpiresAt); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		User:                  user,
		Token:                 accessToken,
		TokenExpiresAt:        accessExpiresAt,
		RefreshToken:          newRefreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// Logout revokes the current refresh token session.
func (s *userServiceImpl) Logout(ec *appcontext.GinContext, request RefreshInput) error {
	refreshToken := strings.TrimSpace(request.RefreshToken)
	if refreshToken == "" {
		return ErrInvalidRefreshToken
	}

	if s.jwtManager == nil {
		return fmt.Errorf("%w: missing jwt manager", ErrUserInternal)
	}

	claims, err := s.jwtManager.ExtractRefreshClaims(refreshToken)
	if err != nil {
		return ErrInvalidRefreshToken
	}

	user, err := s.userRepository.FindByID(ec, claims.Subject)
	if err != nil {
		if errors.Is(err, userrepository.ErrRecordNotFound) {
			return ErrInvalidRefreshToken
		}
		return translateUserRepositoryError(err)
	}

	if s.auditService == nil {
		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(ec, claims.ID, user.ID); err != nil {
			if errors.Is(err, userrepository.ErrRecordNotFound) {
				return ErrInvalidRefreshToken
			}
			return translateUserRepositoryError(err)
		}
		return nil
	}
	runner := s.transactionRunner
	if runner == nil {
		runner = platformdb.RequestTransactionRunner{}
	}
	return runner.Run(ec, func(txContext *appcontext.GinContext) error {
		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(txContext, claims.ID, user.ID); err != nil {
			if errors.Is(err, userrepository.ErrRecordNotFound) {
				return ErrInvalidRefreshToken
			}
			return translateUserRepositoryError(err)
		}
		return s.recordAudit(txContext, auditservice.EventInput{ActorUserID: &user.ID, Action: "auth.logout", ResourceType: "refresh_session", Result: auditservice.ResultSucceeded})
	})
}
