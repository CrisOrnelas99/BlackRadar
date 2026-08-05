// Package controller provides HTTP handlers for user authentication requests.
package controller

import (
	"errors"
	"net/http"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	userservice "blackradar/api/service/user"
)

// UserController handles authentication requests.
type UserController struct {
	userService         userservice.UserService
	secureRefreshCookie bool
}

// NewUserController creates a new UserController instance.
func NewUserController(userService userservice.UserService, secureRefreshCookie bool) *UserController {
	return &UserController{
		userService:         userService,
		secureRefreshCookie: secureRefreshCookie,
	}
}

// CreateUser handles administrator requests to provision a standard user.
func (c *UserController) CreateUser(ec *appcontext.GinContext) {
	var request CreateUserRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	user, err := c.userService.CreateUser(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error creating user")
		return
	}

	ec.JSON(http.StatusCreated, ToUserResponse(user))
}

// Login handles user authentication requests and returns credentials.
func (c *UserController) Login(ec *appcontext.GinContext) {
	var request LoginRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	loginResponse, err := c.userService.Login(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error logging in")
		return
	}

	setRefreshTokenCookie(ec, loginResponse, c.secureRefreshCookie)
	ec.JSON(http.StatusOK, ToLoginResponse(loginResponse))
}

// Refresh exchanges a refresh token for fresh credentials.
func (c *UserController) Refresh(ec *appcontext.GinContext) {
	refreshToken, err := refreshTokenFromCookie(ec)
	if err != nil {
		handleUserServiceError(ec, err)
		return
	}

	refreshResponse, err := c.userService.Refresh(ec, userservice.RefreshInput{RefreshToken: refreshToken})
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error refreshing token")
		return
	}

	setRefreshTokenCookie(ec, refreshResponse, c.secureRefreshCookie)
	ec.JSON(http.StatusOK, ToLoginResponse(refreshResponse))
}

// Logout revokes the current refresh token session.
func (c *UserController) Logout(ec *appcontext.GinContext) {
	refreshToken, err := refreshTokenFromCookie(ec)
	if err != nil {
		clearRefreshTokenCookie(ec, c.secureRefreshCookie)
		ec.Status(http.StatusOK)
		return
	}

	if err := c.userService.Logout(ec, userservice.RefreshInput{RefreshToken: refreshToken}); err != nil {
		clearRefreshTokenCookie(ec, c.secureRefreshCookie)
		if errors.Is(err, userservice.ErrInvalidRefreshToken) {
			ec.Status(http.StatusOK)
			return
		}
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error logging out")
		return
	}

	clearRefreshTokenCookie(ec, c.secureRefreshCookie)
	ec.Status(http.StatusOK)
}
