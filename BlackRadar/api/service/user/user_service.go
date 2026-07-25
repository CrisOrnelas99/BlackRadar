// Package service provides user application services.
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
	"blackradar/api/model"
	"blackradar/api/platform/config"
	appcontext "blackradar/api/platform/requestcontext"
	userrepository "blackradar/api/repository/user"
)

type RegisterInput struct {
	Username string
	Email    string
	Password string
}

type LoginInput struct {
	UserOrEmail string
	Password    string
}

type RefreshInput struct {
	RefreshToken string
}

type LoginResult struct {
	User                  model.User
	Token                 string
	TokenExpiresAt        time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

type userServiceImpl struct {
	jwtManager               *commonjwt.Manager
	userRepository           userrepository.UserRepositoryInterface
	refreshSessionRepository userrepository.RefreshSessionRepositoryInterface
}

// NewUserService creates a user service backed by the supplied dependencies.
func NewUserService(jwtManager *commonjwt.Manager, userRepository userrepository.UserRepositoryInterface, refreshSessionRepository userrepository.RefreshSessionRepositoryInterface) *userServiceImpl {
	return &userServiceImpl{jwtManager: jwtManager, userRepository: userRepository, refreshSessionRepository: refreshSessionRepository}
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
		return model.User{}, err
	}

	user, err := s.userRepository.Save(ec, model.User{
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return LoginResult{}, ErrInvalidLoginCredentials
		}
		return LoginResult{}, translateUserRepositoryError(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		return LoginResult{}, ErrInvalidLoginCredentials
	}

	if s.jwtManager == nil {
		return LoginResult{}, fmt.Errorf("missing jwt manager")
	}

	refreshTokenID, err := commontoken.NewID()
	if err != nil {
		return LoginResult{}, fmt.Errorf("create refresh session token ID: %w", err)
	}
	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	token, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, refreshTokenID)
	if err != nil {
		return LoginResult{}, err
	}
	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Username, refreshTokenID)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.saveRefreshSession(ec, user.ID, refreshTokenID, refreshExpiresAt); err != nil {
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

// normalizeRegisterInput trims and normalizes registration input.
func normalizeRegisterInput(request RegisterInput) RegisterInput {
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Password = strings.TrimSpace(request.Password)
	return request
}

// validateRegisterInput validates the fields required to create an account.
func validateRegisterInput(request RegisterInput) error {
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

// translateUserRepositoryError maps repository errors to user service sentinels.
func translateUserRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, userrepository.ErrRecordNotFound):
		return fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	case errors.Is(err, userrepository.ErrUniqueViolation):
		return fmt.Errorf("%w: %w", ErrUsernameAlreadyExists, err)
	case errors.Is(err, userrepository.ErrNotNullViolation),
		errors.Is(err, userrepository.ErrForeignKeyViolation):
		return fmt.Errorf("%w: %w", ErrInvalidRegisterRequest, err)
	default:
		return fmt.Errorf("%w: %w", ErrUserDependency, err)
	}
}

// Refresh validates a refresh token and returns rotated credentials.
func (s *userServiceImpl) Refresh(ec *appcontext.GinContext, request RefreshInput) (LoginResult, error) {
	refreshToken := strings.TrimSpace(request.RefreshToken)
	if refreshToken == "" {
		return LoginResult{}, ErrInvalidRefreshToken
	}

	if s.jwtManager == nil {
		return LoginResult{}, fmt.Errorf("missing jwt manager")
	}

	claims, err := s.jwtManager.ExtractRefreshClaims(refreshToken)
	if err != nil {
		return LoginResult{}, ErrInvalidRefreshToken
	}

	user, err := s.userRepository.FindByID(ec, claims.Subject)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return LoginResult{}, ErrInvalidRefreshToken
		}
		return LoginResult{}, translateUserRepositoryError(err)
	}

	session, err := s.refreshSessionRepository.FindActiveByTokenIDForUser(ec, claims.ID, user.ID)
	if err != nil {
		if errors.Is(err, userrepository.ErrRecordNotFound) {
			return LoginResult{}, ErrInvalidRefreshToken
		}
		return LoginResult{}, translateUserRepositoryError(err)
	}

	if session.UserID != user.ID {
		return LoginResult{}, ErrInvalidRefreshToken
	}

	newRefreshTokenID, err := commontoken.NewID()
	if err != nil {
		return LoginResult{}, fmt.Errorf("create refresh session token ID: %w", err)
	}
	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, newRefreshTokenID)
	if err != nil {
		return LoginResult{}, err
	}
	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Username, newRefreshTokenID)
	if err != nil {
		return LoginResult{}, err
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
		return translateUserRepositoryError(err)
	}

	if err := s.refreshSessionRepository.RevokeByTokenIDForUser(ec, claims.ID, user.ID); err != nil {
		if errors.Is(err, userrepository.ErrRecordNotFound) {
			return ErrInvalidRefreshToken
		}
		return translateUserRepositoryError(err)
	}

	return nil
}

func (s *userServiceImpl) saveRefreshSession(ec *appcontext.GinContext, userID string, tokenID string, expiresAt time.Time) error {
	return translateUserRepositoryError(s.refreshSessionRepository.Save(ec, model.RefreshSession{
		TokenID:    tokenID,
		UserID:     userID,
		DeviceName: requestDeviceName(ec),
		ExpiresAt:  expiresAt,
	}))
}

func (s *userServiceImpl) rotateRefreshSession(ec *appcontext.GinContext, session model.RefreshSession, newTokenID string, expiresAt time.Time) error {
	newSession := model.RefreshSession{
		TokenID:    newTokenID,
		UserID:     session.UserID,
		DeviceName: session.DeviceName,
		ExpiresAt:  expiresAt,
	}

	if ec == nil || ec.Database() == nil {
		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(ec, session.TokenID, session.UserID); err != nil {
			return translateUserRepositoryError(err)
		}
		return translateUserRepositoryError(s.refreshSessionRepository.Save(ec, newSession))
	}

	transactionDatabase := ec.Database()
	return transactionDatabase.WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		txContext := *ec
		txContext.SetDatabase(tx)

		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(&txContext, session.TokenID, session.UserID); err != nil {
			return translateUserRepositoryError(err)
		}
		if err := s.refreshSessionRepository.Save(&txContext, newSession); err != nil {
			return translateUserRepositoryError(err)
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
