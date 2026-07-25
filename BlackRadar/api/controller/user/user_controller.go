// Package controller provides HTTP handlers for user authentication requests.
package controller

import (
	"net/http"

	shared "blackradar/api/controller/shared"
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
	if shared.BindJSON(ec, &request) {
		return
	}

	user, err := c.userService.Register(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error registering user")
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

	ec.JSON(http.StatusOK, ToLoginResponse(loginResponse))
}

// Refresh exchanges a refresh token for fresh credentials.
func (c *UserController) Refresh(ec *appcontext.GinContext) {
	var request RefreshRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	refreshResponse, err := c.userService.Refresh(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error refreshing token")
		return
	}

	ec.JSON(http.StatusOK, ToLoginResponse(refreshResponse))
}

// Logout revokes the current refresh token session.
func (c *UserController) Logout(ec *appcontext.GinContext) {
	var request RefreshRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	if err := c.userService.Logout(ec, request.ToServiceInput()); err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error logging out")
		return
	}

	ec.Status(http.StatusOK)
}
