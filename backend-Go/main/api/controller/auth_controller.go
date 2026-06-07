package controller

import (
	"errors"
	"net/http"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/controller/controller_utils"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/service"
)

type AuthController struct{}

func NewAuthController() *AuthController {
	return &AuthController{}
}

func (c *AuthController) Register(ec *appcontext.EchoContext) {
	var request model.RegisterRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		controller_utils.HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	authService := service.GetAuthServiceFromEchoContext(ec)
	if err := authService.Register(ec, request); err != nil {
		if handleAuthServiceError(ec, err, "Error registering user") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error registering user")
		return
	}

	ec.Status(http.StatusOK)
}

func (c *AuthController) Login(ec *appcontext.EchoContext) {
	var request model.LoginRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		controller_utils.HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	authService := service.GetAuthServiceFromEchoContext(ec)
	token, err := authService.Login(ec, request)
	if err != nil {
		if handleAuthServiceError(ec, err, "Error logging in") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error logging in")
		return
	}

	ec.JSON(http.StatusOK, model.LoginResponse{Token: token})
}

func handleAuthServiceError(ec *appcontext.EchoContext, err error, fallbackMessage string) bool {
	var validationErr *service.ValidationError
	if errors.As(err, &validationErr) {
		controller_utils.HandleError(ec, http.StatusBadRequest, err, validationErr.Error())
		return true
	}

	var unauthorizedErr *service.UnauthorizedError
	if errors.As(err, &unauthorizedErr) || errors.Is(err, service.ErrInvalidCredentials) {
		controller_utils.HandleError(ec, http.StatusUnauthorized, err, "Invalid credentials.")
		return true
	}

	var forbiddenErr *service.ForbiddenError
	if errors.As(err, &forbiddenErr) {
		controller_utils.HandleError(ec, http.StatusForbidden, err, forbiddenErr.Error())
		return true
	}

	return false
}
