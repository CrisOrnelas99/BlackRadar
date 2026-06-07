package controller

import (
	"errors"
	"net/http"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/service"
)

type AuthController struct {
	authService service.AuthService
}

func NewAuthController(authService service.AuthService) *AuthController {
	return &AuthController{authService: authService}
}

func (c *AuthController) Register(ec *appcontext.GinContext) {
	var request dto.RegisterRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if err := c.authService.Register(ec, request); err != nil {
		if handleAuthServiceError(ec, err, "Error registering user") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error registering user")
		return
	}

	ec.Status(http.StatusOK)
}

func (c *AuthController) Login(ec *appcontext.GinContext) {
	var request dto.LoginRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	loginResponse, err := c.authService.Login(ec, request)
	if err != nil {
		if handleAuthServiceError(ec, err, "Error logging in") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error logging in")
		return
	}

	ec.JSON(http.StatusOK, loginResponse)
}

func handleAuthServiceError(ec *appcontext.GinContext, err error, fallbackMessage string) bool {
	var validationErr *service.ValidationError
	if errors.As(err, &validationErr) {
		HandleError(ec, http.StatusBadRequest, err, validationErr.Error())
		return true
	}

	var unauthorizedErr *service.UnauthorizedError
	if errors.As(err, &unauthorizedErr) || errors.Is(err, service.ErrInvalidCredentials) {
		HandleError(ec, http.StatusUnauthorized, err, "Invalid credentials.")
		return true
	}

	var forbiddenErr *service.ForbiddenError
	if errors.As(err, &forbiddenErr) {
		HandleError(ec, http.StatusForbidden, err, forbiddenErr.Error())
		return true
	}

	return false
}
