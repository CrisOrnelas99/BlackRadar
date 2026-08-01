// Package service provides user application services.
package service

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	commonjwt "blackradar/api/common/jwt"
	commontoken "blackradar/api/common/token"
	"blackradar/api/model"
	"blackradar/api/platform/config"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	transactionboundary "blackradar/api/platform/transaction"
	userrepository "blackradar/api/repository/user"
	auditservice "blackradar/api/service/audit"
)

// RegisterInput contains the fields required to create a user account.
type RegisterInput struct {
	Username string
	Email    string
	Password string
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
}

// NewUserService creates a user service backed by the supplied dependencies.
func NewUserService(jwtManager *commonjwt.Manager, userRepository userrepository.UserRepositoryInterface, refreshSessionRepository userrepository.RefreshSessionRepositoryInterface, auditServices ...auditservice.Service) *userServiceImpl {
	service := &userServiceImpl{
		jwtManager:               jwtManager,
		userRepository:           userRepository,
		refreshSessionRepository: refreshSessionRepository,
		transactionRunner:        platformdb.RequestTransactionRunner{},
	}
	if len(auditServices) > 0 {
		service.auditService = auditServices[0]
	}
	return service
}

// Register validates and creates a new user account.
func (s *userServiceImpl) Register(ec *appcontext.GinContext, request RegisterInput) (model.User, error) {
	request = normalizeRegisterInput(request)
	if err := validateRegisterInput(request); err != nil {
		return model.User{}, ErrInvalidRegisterRequest
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

	user, err := s.userRepository.CreateUser(ec, model.User{
		Username:     request.Username,
		Email:        request.Email,
		Role:         model.RoleUser,
		PasswordHash: string(hash),
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
	if request.UserOrEmail == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
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
			if auditErr := s.recordAudit(ec, auditservice.EventInput{Action: "auth.login", ResourceType: "user", Result: auditservice.ResultDenied}); auditErr != nil {
				return LoginResult{}, auditErr
			}
			return LoginResult{}, ErrInvalidLoginCredentials
		}
		return LoginResult{}, translateUserRepositoryError(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		if err := s.recordAudit(ec, auditservice.EventInput{Action: "auth.login", ResourceType: "user", Result: auditservice.ResultDenied}); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, ErrInvalidLoginCredentials
	}

	if s.jwtManager == nil {
		return LoginResult{}, fmt.Errorf("%w: missing jwt manager", ErrUserInternal)
	}

	refreshTokenID, err := commontoken.NewID()
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: create refresh session token ID: %w", ErrUserInternal, err)
	}
	now := time.Now().UTC()
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
