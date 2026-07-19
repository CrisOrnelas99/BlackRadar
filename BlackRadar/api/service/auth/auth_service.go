// Package service provides authentication application services.
package service

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	commonjwt "blackradar/api/common/jwt"
	commontoken "blackradar/api/common/token"
	"blackradar/api/controller/dto"
	"blackradar/api/model"
	"blackradar/api/platform/config"
	appcontext "blackradar/api/platform/requestcontext"
	baserepository "blackradar/api/repository"
	userrepository "blackradar/api/repository/user"
	baseservice "blackradar/api/service"
)

type authServiceImpl struct {
	jwtManager               *commonjwt.Manager
	userRepository           baserepository.UserRepository
	refreshSessionRepository baserepository.RefreshSessionRepository
}

// NewAuthService creates an authentication service backed by the supplied dependencies.
func NewAuthService(jwtManager *commonjwt.Manager, userRepository baserepository.UserRepository, refreshSessionRepository baserepository.RefreshSessionRepository) baseservice.AuthService {
	return &authServiceImpl{jwtManager: jwtManager, userRepository: userRepository, refreshSessionRepository: refreshSessionRepository}
}

// Register validates and creates a new user account.
func (s *authServiceImpl) Register(ec *appcontext.GinContext, request dto.RegisterRequest) (dto.UserResponse, error) {
	request = normalizeRegisterRequest(request)
	if err := validateRegisterRequest(request); err != nil {
		return dto.UserResponse{}, ErrInvalidRegisterRequest
	}

	exists, err := s.userRepository.ExistsByUsername(ec, request.Username)
	if err != nil {
		return dto.UserResponse{}, translateAuthRepositoryError(err)
	}
	if exists {
		return dto.UserResponse{}, ErrUsernameAlreadyExists
	}

	exists, err = s.userRepository.ExistsByEmail(ec, request.Email)
	if err != nil {
		return dto.UserResponse{}, translateAuthRepositoryError(err)
	}
	if exists {
		return dto.UserResponse{}, ErrEmailAlreadyExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), config.PasswordCost())
	if err != nil {
		return dto.UserResponse{}, err
	}

	user, err := s.userRepository.Save(ec, model.User{
		Username:     request.Username,
		Email:        request.Email,
		Role:         model.RoleUser,
		PasswordHash: string(hash),
	})
	if err != nil {
		return dto.UserResponse{}, translateAuthRepositoryError(err)
	}

	return dto.ToUserResponse(user), nil
}

// Login validates credentials and returns a signed access token.
func (s *authServiceImpl) Login(ec *appcontext.GinContext, request dto.LoginRequest) (dto.LoginResponse, error) {
	request.UserOrEmail = strings.TrimSpace(request.UserOrEmail)
	isEmailLogin := isEmailLikeLoginIdentifier(request.UserOrEmail)
	if isEmailLogin {
		request.UserOrEmail = strings.ToLower(request.UserOrEmail)
	}
	if request.UserOrEmail == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		return dto.LoginResponse{}, ErrInvalidLoginCredentials
	}

	var user model.User
	var err error
	if isEmailLogin {
		user, err = s.userRepository.FindByEmail(ec, request.UserOrEmail)
	} else {
		user, err = s.userRepository.FindByUsername(ec, request.UserOrEmail)
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.LoginResponse{}, ErrInvalidLoginCredentials
		}
		return dto.LoginResponse{}, translateAuthRepositoryError(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		return dto.LoginResponse{}, ErrInvalidLoginCredentials
	}

	if s.jwtManager == nil {
		return dto.LoginResponse{}, fmt.Errorf("missing jwt manager")
	}

	refreshTokenID, err := commontoken.NewID()
	if err != nil {
		return dto.LoginResponse{}, fmt.Errorf("create refresh session token ID: %w", err)
	}
	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	token, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, refreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Username, refreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	if err := s.saveRefreshSession(ec, user.ID, refreshTokenID, refreshExpiresAt); err != nil {
		return dto.LoginResponse{}, err
	}

	return dto.LoginResponse{
		User:                  dto.ToUserResponse(user),
		Token:                 token,
		TokenExpiresAt:        accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// normalizeRegisterRequest trims and normalizes registration input.
func normalizeRegisterRequest(request dto.RegisterRequest) dto.RegisterRequest {
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Password = strings.TrimSpace(request.Password)
	return request
}

// validateRegisterRequest validates the fields required to create an account.
func validateRegisterRequest(request dto.RegisterRequest) error {
	if strings.TrimSpace(request.Username) == "" || utf8.RuneCountInString(request.Username) < 3 || utf8.RuneCountInString(request.Username) > 50 || strings.Contains(request.Username, "@") {
		return ErrInvalidRegisterRequest
	}
	if strings.TrimSpace(request.Password) == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		return ErrInvalidRegisterRequest
	}
	if strings.TrimSpace(request.Email) == "" {
		return ErrInvalidRegisterRequest
	}
	if _, err := mail.ParseAddress(request.Email); err != nil {
		return fmt.Errorf("%w: invalid email", ErrInvalidRegisterRequest)
	}
	return nil
}

// isEmailLikeLoginIdentifier reports whether the login identifier should be treated as an email address.
func isEmailLikeLoginIdentifier(value string) bool {
	return strings.Contains(strings.TrimSpace(value), "@")
}

// translateAuthRepositoryError maps repository errors to auth service sentinels.
func translateAuthRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, userrepository.ErrRefreshSessionNotFound):
		return fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	case errors.Is(err, userrepository.ErrDuplicateData):
		return fmt.Errorf("%w: %w", ErrUsernameAlreadyExists, err)
	case errors.Is(err, userrepository.ErrInvalidData),
		errors.Is(err, userrepository.ErrInvalidReference):
		return fmt.Errorf("%w: %w", ErrInvalidRegisterRequest, err)
	default:
		return fmt.Errorf("%w: %w", ErrAuthInternal, err)
	}
}

// Refresh validates a refresh token and returns rotated credentials.
func (s *authServiceImpl) Refresh(ec *appcontext.GinContext, request dto.RefreshRequest) (dto.LoginResponse, error) {
	refreshToken := strings.TrimSpace(request.RefreshToken)
	if refreshToken == "" {
		return dto.LoginResponse{}, ErrInvalidRefreshToken
	}

	if s.jwtManager == nil {
		return dto.LoginResponse{}, fmt.Errorf("missing jwt manager")
	}

	claims, err := s.jwtManager.ExtractRefreshClaims(refreshToken)
	if err != nil {
		return dto.LoginResponse{}, ErrInvalidRefreshToken
	}

	user, err := s.userRepository.FindByID(ec, claims.Subject)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.LoginResponse{}, ErrInvalidRefreshToken
		}
		return dto.LoginResponse{}, translateAuthRepositoryError(err)
	}

	session, err := s.refreshSessionRepository.FindActiveByTokenIDForUser(ec, claims.ID, user.ID)
	if err != nil {
		if errors.Is(err, userrepository.ErrRefreshSessionNotFound) {
			return dto.LoginResponse{}, ErrInvalidRefreshToken
		}
		return dto.LoginResponse{}, translateAuthRepositoryError(err)
	}

	if session.UserID != user.ID {
		return dto.LoginResponse{}, ErrInvalidRefreshToken
	}

	newRefreshTokenID, err := commontoken.NewID()
	if err != nil {
		return dto.LoginResponse{}, fmt.Errorf("create refresh session token ID: %w", err)
	}
	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, newRefreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Username, newRefreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	if err := s.rotateRefreshSession(ec, session, newRefreshTokenID, refreshExpiresAt); err != nil {
		return dto.LoginResponse{}, err
	}

	return dto.LoginResponse{
		User:                  dto.ToUserResponse(user),
		Token:                 accessToken,
		TokenExpiresAt:        accessExpiresAt,
		RefreshToken:          newRefreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// Logout revokes the current refresh token session.
func (s *authServiceImpl) Logout(ec *appcontext.GinContext, request dto.RefreshRequest) error {
	refreshToken := strings.TrimSpace(request.RefreshToken)
	if refreshToken == "" {
		return ErrInvalidRefreshToken
	}

	if s.jwtManager == nil {
		return fmt.Errorf("missing jwt manager")
	}

	claims, err := s.jwtManager.ExtractRefreshClaims(refreshToken)
	if err != nil {
		return ErrInvalidRefreshToken
	}

	user, err := s.userRepository.FindByID(ec, claims.Subject)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInvalidRefreshToken
		}
		return translateAuthRepositoryError(err)
	}

	if err := s.refreshSessionRepository.RevokeByTokenIDForUser(ec, claims.ID, user.ID); err != nil {
		if errors.Is(err, userrepository.ErrRefreshSessionNotFound) {
			return ErrInvalidRefreshToken
		}
		return translateAuthRepositoryError(err)
	}

	return nil
}

func (s *authServiceImpl) saveRefreshSession(ec *appcontext.GinContext, userID string, tokenID string, expiresAt time.Time) error {
	return translateAuthRepositoryError(s.refreshSessionRepository.Save(ec, model.RefreshSession{
		TokenID:    tokenID,
		UserID:     userID,
		DeviceName: requestDeviceName(ec),
		ExpiresAt:  expiresAt,
	}))
}

func (s *authServiceImpl) rotateRefreshSession(ec *appcontext.GinContext, session model.RefreshSession, newTokenID string, expiresAt time.Time) error {
	newSession := model.RefreshSession{
		TokenID:    newTokenID,
		UserID:     session.UserID,
		DeviceName: session.DeviceName,
		ExpiresAt:  expiresAt,
	}

	if ec == nil || ec.Database() == nil {
		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(ec, session.TokenID, session.UserID); err != nil {
			return translateAuthRepositoryError(err)
		}
		return translateAuthRepositoryError(s.refreshSessionRepository.Save(ec, newSession))
	}

	transactionDatabase := ec.Database()
	return transactionDatabase.WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		txContext := *ec
		txContext.SetDatabase(tx)

		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(&txContext, session.TokenID, session.UserID); err != nil {
			return translateAuthRepositoryError(err)
		}
		if err := s.refreshSessionRepository.Save(&txContext, newSession); err != nil {
			return translateAuthRepositoryError(err)
		}
		return nil
	})
}

func requestDeviceName(ec *appcontext.GinContext) string {
	if ec == nil || ec.Context == nil || ec.Request == nil {
		return "unknown"
	}
	deviceName := strings.TrimSpace(ec.Request.UserAgent())
	if deviceName == "" {
		return "unknown"
	}
	if len(deviceName) > 255 {
		return deviceName[:255]
	}
	return deviceName
}
