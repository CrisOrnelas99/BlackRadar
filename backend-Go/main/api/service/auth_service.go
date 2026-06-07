package service

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/repository"
	"secureops/backend-go/api/security"
)

type AuthService interface {
	Register(ec *appcontext.EchoContext, request model.RegisterRequest) error
	Login(ec *appcontext.EchoContext, request model.LoginRequest) (string, error)
}

type authServiceImpl struct {
	jwtService *security.JwtService
}

var defaultJwtService *security.JwtService

func NewAuthService(jwtService *security.JwtService) AuthService {
	defaultJwtService = jwtService
	return &authServiceImpl{jwtService: jwtService}
}

func GetAuthServiceFromEchoContext(ec *appcontext.EchoContext) AuthService {
	if ec != nil {
		if value, exists := ec.Get(appcontext.AuthServiceKey); exists {
			if service, ok := value.(AuthService); ok {
				return service
			}
		}

		authService := &authServiceImpl{jwtService: defaultJwtService}
		ec.Set(appcontext.AuthServiceKey, authService)
		return authService
	}

	return &authServiceImpl{jwtService: defaultJwtService}
}

func (s *authServiceImpl) Register(ec *appcontext.EchoContext, request model.RegisterRequest) error {
	if err := validateRegisterRequest(request); err != nil {
		return err
	}

	userRepository := repository.GetUserRepoFromEchoContext(ec)

	exists, err := userRepository.ExistsByUsername(ec, request.Username)
	if err != nil {
		return s.translateRepositoryError(err)
	}
	if exists {
		return ErrConflict
	}

	exists, err = userRepository.ExistsByEmail(ec, request.Email)
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

	return s.translateRepositoryError(userRepository.Save(ec, model.User{
		Username:     request.Username,
		Email:        request.Email,
		PasswordHash: string(hash),
	}))
}

func (s *authServiceImpl) Login(ec *appcontext.EchoContext, request model.LoginRequest) (string, error) {
	if strings.TrimSpace(request.UserOrEmail) == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		return "", ErrInvalidCredentials
	}

	userRepository := repository.GetUserRepoFromEchoContext(ec)

	user, err := userRepository.FindByUsernameOrEmail(ec, request.UserOrEmail)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", ErrInvalidCredentials
		}
		return "", s.translateRepositoryError(err)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)) != nil {
		return "", ErrInvalidCredentials
	}

	if s.jwtService == nil {
		return "", fmt.Errorf("%w: missing jwt service", ErrRemoteService)
	}

	return s.jwtService.GenerateToken(user.Username)
}

func validateRegisterRequest(request model.RegisterRequest) error {
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
