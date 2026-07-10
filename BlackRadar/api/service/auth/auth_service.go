// Package service provides authentication application services.
package service

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"blackradar/api/config"
	appcontext "blackradar/api/context"
	"blackradar/api/dto"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
	"blackradar/api/security"
	baseservice "blackradar/api/service"
	"blackradar/api/utils"
)

type authServiceImpl struct {
	jwtManager               *security.JWTManager
	organizationRepository   baserepository.OrganizationRepository
	userRepository           baserepository.UserRepository
	refreshSessionRepository baserepository.RefreshSessionRepository
}

// NewAuthService creates an authentication service backed by the supplied dependencies.
func NewAuthService(jwtManager *security.JWTManager, organizationRepository baserepository.OrganizationRepository, userRepository baserepository.UserRepository, refreshSessionRepository baserepository.RefreshSessionRepository) baseservice.AuthService {
	return &authServiceImpl{jwtManager: jwtManager, organizationRepository: organizationRepository, userRepository: userRepository, refreshSessionRepository: refreshSessionRepository}
}

// Register validates and creates a new user account.
func (s *authServiceImpl) Register(ec *appcontext.GinContext, request dto.RegisterRequest) (dto.UserResponse, error) {
	request = baseservice.NormalizeRegisterRequest(request)
	if err := baseservice.ValidateRegisterRequest(request); err != nil {
		return dto.UserResponse{}, err
	}

	exists, err := s.userRepository.ExistsByUsername(ec, request.Username)
	if err != nil {
		return dto.UserResponse{}, baseservice.TranslateRepositoryError(err)
	}
	if exists {
		return dto.UserResponse{}, baseservice.ErrConflict
	}

	organization, err := s.findOrCreateOrganization(ec, request.Organization)
	if err != nil {
		return dto.UserResponse{}, err
	}

	exists, err = s.userRepository.ExistsByEmail(ec, request.Email)
	if err != nil {
		return dto.UserResponse{}, baseservice.TranslateRepositoryError(err)
	}
	if exists {
		return dto.UserResponse{}, baseservice.ErrConflict
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), config.PasswordCost())
	if err != nil {
		return dto.UserResponse{}, err
	}

	user, err := s.userRepository.Save(ec, model.User{
		OrganizationID: organization.ID,
		Username:       request.Username,
		Email:          request.Email,
		Role:           model.RoleUser,
		PasswordHash:   string(hash),
	})
	if err != nil {
		return dto.UserResponse{}, baseservice.TranslateRepositoryError(err)
	}

	return dto.ToUserResponse(user, organization.Name), nil
}

func (s *authServiceImpl) findOrCreateOrganization(ec *appcontext.GinContext, organizationName string) (model.Organization, error) {
	if s.organizationRepository == nil {
		return model.Organization{}, fmt.Errorf("missing organization repository")
	}

	normalizedName := strings.ToLower(strings.TrimSpace(organizationName))
	organization, err := s.organizationRepository.FindByName(ec, normalizedName)
	if err == nil {
		return organization, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Organization{}, baseservice.TranslateRepositoryError(err)
	}

	created, err := s.organizationRepository.Save(ec, model.Organization{Name: normalizedName})
	if err != nil {
		return model.Organization{}, baseservice.TranslateRepositoryError(err)
	}
	return created, nil
}

// Login validates credentials and returns a signed access token.
func (s *authServiceImpl) Login(ec *appcontext.GinContext, request dto.LoginRequest) (dto.LoginResponse, error) {
	request.UserOrEmail = strings.TrimSpace(request.UserOrEmail)
	isEmailLogin := baseservice.IsEmailLikeLoginIdentifier(request.UserOrEmail)
	if isEmailLogin {
		request.UserOrEmail = strings.ToLower(request.UserOrEmail)
	}
	if request.UserOrEmail == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
	}

	var user model.User
	var err error
	if isEmailLogin {
		user, err = s.userRepository.FindByEmail(ec, request.UserOrEmail)
	} else {
		user, err = s.userRepository.FindByUsername(ec, request.UserOrEmail)
	}
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
		}
		return dto.LoginResponse{}, baseservice.TranslateRepositoryError(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
	}

	organization, err := s.organizationRepository.FindByID(ec, user.OrganizationID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
		}
		return dto.LoginResponse{}, baseservice.TranslateRepositoryError(err)
	}

	if s.jwtManager == nil {
		return dto.LoginResponse{}, fmt.Errorf("missing jwt manager")
	}

	refreshTokenID := utils.NewTokenID()
	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	token, err := s.jwtManager.GenerateToken(user.Username, refreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.Username, refreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	if err := s.saveRefreshSession(ec, user.ID, refreshTokenID, refreshExpiresAt); err != nil {
		return dto.LoginResponse{}, err
	}

	return dto.LoginResponse{
		User:                  dto.ToUserResponse(user, organization.Name),
		Token:                 token,
		TokenExpiresAt:        accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}, nil
}

// Refresh validates a refresh token and returns rotated credentials.
func (s *authServiceImpl) Refresh(ec *appcontext.GinContext, request dto.RefreshRequest) (dto.LoginResponse, error) {
	refreshToken := strings.TrimSpace(request.RefreshToken)
	if refreshToken == "" {
		return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
	}

	if s.jwtManager == nil {
		return dto.LoginResponse{}, fmt.Errorf("missing jwt manager")
	}

	claims, err := s.jwtManager.ExtractRefreshClaims(refreshToken)
	if err != nil {
		return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
	}

	user, err := s.userRepository.FindByUsername(ec, claims.Subject)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
		}
		return dto.LoginResponse{}, baseservice.TranslateRepositoryError(err)
	}

	session, err := s.refreshSessionRepository.FindActiveByTokenIDForUser(ec, claims.ID, user.ID)
	if err != nil {
		return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
	}

	if session.UserID != user.ID {
		return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
	}

	organization, err := s.organizationRepository.FindByID(ec, user.OrganizationID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.LoginResponse{}, baseservice.ErrInvalidCredentials
		}
		return dto.LoginResponse{}, baseservice.TranslateRepositoryError(err)
	}

	newRefreshTokenID := utils.NewTokenID()
	now := time.Now().UTC()
	accessExpiresAt := now.Add(s.jwtManager.AccessExpiration())
	refreshExpiresAt := now.Add(s.jwtManager.RefreshExpiration())
	accessToken, err := s.jwtManager.GenerateToken(user.Username, newRefreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.Username, newRefreshTokenID)
	if err != nil {
		return dto.LoginResponse{}, err
	}
	if err := s.rotateRefreshSession(ec, session, newRefreshTokenID, refreshExpiresAt); err != nil {
		return dto.LoginResponse{}, err
	}

	return dto.LoginResponse{
		User:                  dto.ToUserResponse(user, organization.Name),
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
		return baseservice.ErrInvalidCredentials
	}

	if s.jwtManager == nil {
		return fmt.Errorf("missing jwt manager")
	}

	claims, err := s.jwtManager.ExtractRefreshClaims(refreshToken)
	if err != nil {
		return baseservice.ErrInvalidCredentials
	}

	user, err := s.userRepository.FindByUsername(ec, claims.Subject)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return baseservice.ErrInvalidCredentials
		}
		return baseservice.TranslateRepositoryError(err)
	}

	if err := s.refreshSessionRepository.RevokeByTokenIDForUser(ec, claims.ID, user.ID); err != nil {
		if errors.Is(err, baserepository.ErrRefreshSessionNotFound) {
			return baseservice.ErrInvalidCredentials
		}
		return baseservice.TranslateRepositoryError(err)
	}

	return nil
}

func (s *authServiceImpl) saveRefreshSession(ec *appcontext.GinContext, userID string, tokenID string, expiresAt time.Time) error {
	return s.refreshSessionRepository.Save(ec, model.RefreshSession{
		TokenID:    tokenID,
		UserID:     userID,
		DeviceName: requestDeviceName(ec),
		ExpiresAt:  expiresAt,
	})
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
			return baseservice.TranslateRepositoryError(err)
		}
		return s.refreshSessionRepository.Save(ec, newSession)
	}

	transactionDatabase := ec.Database()
	return transactionDatabase.WithContext(ec.RequestContext()).Transaction(func(tx *gorm.DB) error {
		txContext := *ec
		txContext.SetDatabase(tx)

		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(&txContext, session.TokenID, session.UserID); err != nil {
			return baseservice.TranslateRepositoryError(err)
		}
		if err := s.refreshSessionRepository.Save(&txContext, newSession); err != nil {
			return baseservice.TranslateRepositoryError(err)
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
