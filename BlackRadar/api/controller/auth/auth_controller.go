// Package controller provides HTTP handlers for authentication requests.
package controller

import (
	"errors"
	"net/http"

	appcontext "blackradar/api/context"
	basecontroller "blackradar/api/controller"
	"blackradar/api/dto"
	baseservice "blackradar/api/service"
)

// AuthController handles authentication requests.
type AuthController struct {
	authService baseservice.AuthService
}

// NewAuthController creates a new AuthController instance.
func NewAuthController(authService baseservice.AuthService) *AuthController {
	return &AuthController{authService: authService}
}

// Register handles new user registration requests.
func (c *AuthController) Register(ec *appcontext.GinContext) {
	var request dto.RegisterRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	user, err := c.authService.Register(ec, request)
	if err != nil {
		if handleAuthServiceError(ec, err, "Error registering user") {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error registering user")
		return
	}

	ec.JSON(http.StatusCreated, user)
}

// Login handles user authentication requests and returns credentials.
func (c *AuthController) Login(ec *appcontext.GinContext) {
	var request dto.LoginRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	loginResponse, err := c.authService.Login(ec, request)
	if err != nil {
		if handleAuthServiceError(ec, err, "Error logging in") {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error logging in")
		return
	}

	ec.JSON(http.StatusOK, loginResponse)
}

// Refresh exchanges a refresh token for fresh credentials.
func (c *AuthController) Refresh(ec *appcontext.GinContext) {
	var request dto.RefreshRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	refreshResponse, err := c.authService.Refresh(ec, request)
	if err != nil {
		if handleAuthServiceError(ec, err, "Error refreshing token") {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error refreshing token")
		return
	}

	ec.JSON(http.StatusOK, refreshResponse)
}

// Logout revokes the current refresh token session.
func (c *AuthController) Logout(ec *appcontext.GinContext) {
	var request dto.RefreshRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	if err := c.authService.Logout(ec, request); err != nil {
		if handleAuthServiceError(ec, err, "Error logging out") {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error logging out")
		return
	}

	ec.Status(http.StatusOK)
}

// handleAuthServiceError maps auth service sentinels to HTTP responses.
func handleAuthServiceError(ec *appcontext.GinContext, err error, fallbackMessage string) bool {
	var serviceErr *baseservice.ServiceError
	if errors.As(err, &serviceErr) {
		if errors.Is(err, baseservice.ErrInvalidRequestData) {
			basecontroller.HandleError(ec, http.StatusBadRequest, err, baseservice.ErrInvalidRequestData.Error())
			return true
		}
		if errors.Is(err, baseservice.ErrConflict) {
			basecontroller.HandleError(ec, http.StatusConflict, err, baseservice.ErrConflict.Error())
			return true
		}
		if errors.Is(err, baseservice.ErrInvalidCredentials) {
			basecontroller.HandleError(ec, http.StatusUnauthorized, err, "Invalid credentials.")
			return true
		}
		if errors.Is(err, baseservice.ErrForbidden) {
			basecontroller.HandleError(ec, http.StatusForbidden, err, baseservice.ErrForbidden.Error())
			return true
		}
	}

	return false
}
