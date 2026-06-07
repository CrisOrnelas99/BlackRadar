package service

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/security"
)

type AuthService interface {
	Register(ec *appcontext.GinContext, request dto.RegisterRequest) error
	Login(ec *appcontext.GinContext, request dto.LoginRequest) (dto.LoginResponse, error)
}

type authServiceImpl struct {
	jwtService     *security.JwtService
	userRepository UserRepository
}

func NewAuthService(jwtService *security.JwtService, userRepository UserRepository) AuthService {
	return &authServiceImpl{jwtService: jwtService, userRepository: userRepository}
}

func (s *authServiceImpl) Register(ec *appcontext.GinContext, request dto.RegisterRequest) error {
	if err := validateRegisterRequest(request); err != nil {
		return err
	}

	exists, err := s.userRepository.ExistsByUsername(ec, request.Username)
	if err != nil {
		return s.translateRepositoryError(err)
	}
	if exists {
		return ErrConflict
	}

	exists, err = s.userRepository.ExistsByEmail(ec, request.Email)
	if err != nil {
		return s.translateRepositoryError(err)
	}
	if exists {
		return ErrConflict
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.translateRepositoryError(s.userRepository.Save(ec, model.User{
		Username:     request.Username,
		Email:        request.Email,
		PasswordHash: string(hash),
	}))
}

func (s *authServiceImpl) Login(ec *appcontext.GinContext, request dto.LoginRequest) (dto.LoginResponse, error) {
	if strings.TrimSpace(request.UserOrEmail) == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		return dto.LoginResponse{}, ErrInvalidCredentials
	}

	user, err := s.userRepository.FindByUsernameOrEmail(ec, request.UserOrEmail)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return dto.LoginResponse{}, ErrInvalidCredentials
		}
		return dto.LoginResponse{}, s.translateRepositoryError(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		return dto.LoginResponse{}, ErrInvalidCredentials
	}

	if s.jwtService == nil {
		return dto.LoginResponse{}, fmt.Errorf("missing jwt service")
	}

	token, err := s.jwtService.GenerateToken(user.Username)
	if err != nil {
		return dto.LoginResponse{}, err
	}

	return dto.LoginResponse{
		Token: token,
		User:  dto.ToUserResponse(user),
	}, nil
}

func validateRegisterRequest(request dto.RegisterRequest) error {
	usernameLen := utf8.RuneCountInString(request.Username)
	passwordLen := utf8.RuneCountInString(request.Password)

	if usernameLen < 3 || usernameLen > 20 {
		return ErrInvalidRequestData
	}
	if _, err := mail.ParseAddress(request.Email); err != nil {
		return ErrInvalidRequestData
	}
	if passwordLen < 8 || passwordLen > 100 {
		return ErrInvalidRequestData
	}

	return nil
}

func (s *authServiceImpl) translateRepositoryError(err error) error {
	return translateRepositoryError(err)
}
