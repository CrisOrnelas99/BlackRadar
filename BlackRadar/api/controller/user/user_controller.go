// Package controller provides HTTP handlers for user authentication requests.
package controller

import (
	"errors"
	"net/http"

	basecontroller "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	userservice "blackradar/api/service/user"
)

// UserController handles authentication requests.
type UserController struct {
	userService userservice.UserService
}

// NewUserController creates a new UserController instance.
func NewUserController(userService userservice.UserService) *UserController {
	return &UserController{userService: userService}
}

// Register handles new user registration requests.
func (c *UserController) Register(ec *appcontext.GinContext) {
	var request RegisterRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	user, err := c.userService.Register(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error registering user")
		return
	}

	ec.JSON(http.StatusCreated, ToUserResponse(user))
}

// Login handles user authentication requests and returns credentials.
func (c *UserController) Login(ec *appcontext.GinContext) {
	var request LoginRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	loginResponse, err := c.userService.Login(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error logging in")
		return
	}

	ec.JSON(http.StatusOK, ToLoginResponse(loginResponse))
}

// Refresh exchanges a refresh token for fresh credentials.
func (c *UserController) Refresh(ec *appcontext.GinContext) {
	var request RefreshRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	refreshResponse, err := c.userService.Refresh(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error refreshing token")
		return
	}

	ec.JSON(http.StatusOK, ToLoginResponse(refreshResponse))
}

// Logout revokes the current refresh token session.
func (c *UserController) Logout(ec *appcontext.GinContext) {
	var request RefreshRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	if err := c.userService.Logout(ec, request.ToServiceInput()); err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error logging out")
		return
	}

	ec.Status(http.StatusOK)
}

// handleUserServiceError maps user service error categories to HTTP responses.
func handleUserServiceError(ec *appcontext.GinContext, err error) bool {
	var validationErr *userservice.ValidationError
	var conflictErr *userservice.ConflictError
	var unauthorizedErr *userservice.UnauthorizedError
	var dependencyErr *userservice.DependencyError
	var internalErr *userservice.InternalError

	switch {
	case errors.As(err, &validationErr):
		return basecontroller.HandleError(ec, http.StatusBadRequest, err, err.Error())
	case errors.As(err, &conflictErr):
		return basecontroller.HandleError(ec, http.StatusConflict, err, err.Error())
	case errors.As(err, &unauthorizedErr):
		return basecontroller.HandleError(ec, http.StatusUnauthorized, err, "Invalid credentials.")
	case errors.As(err, &dependencyErr):
		return basecontroller.HandleError(ec, http.StatusBadGateway, err, "User dependency unavailable")
	case errors.As(err, &internalErr):
		return basecontroller.HandleError(ec, http.StatusInternalServerError, err, "User service failed")
	}

	return false
}
