// Package controller provides HTTP handlers for user authentication requests.
package controller

import (
	"errors"
	"net/http"

	"blackradar/api/common/pagination"
	shared "blackradar/api/controller/shared"
	"blackradar/api/model"
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

// ListUsers returns safe account summaries for administrators.
func (c *UserController) ListUsers(ec *appcontext.GinContext) {
	query := model.UserListQuery{Pagination: pagination.Request{Page: 1}}
	if err := ec.ShouldBindQuery(&query); err != nil {
		shared.HandleError(ec, http.StatusBadRequest, err, "Invalid user list parameters")
		return
	}
	users, err := c.userService.ListUsers(ec, query)
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving users")
		return
	}
	responses := make([]UserResponse, 0, len(users.Items))
	for _, user := range users.Items {
		responses = append(responses, ToUserResponse(user))
	}
	ec.JSON(http.StatusOK, UserPageResponse{Users: responses, Pagination: users.Metadata()})
}

// GetUserForManagement returns a safe account summary for administrators.
func (c *UserController) GetUserForManagement(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "User ID must be a valid UUID") {
		return
	}
	user, err := c.userService.GetUserForManagement(ec, id)
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving user")
		return
	}
	ec.JSON(http.StatusOK, ToUserResponse(user))
}

// ChangeUserRole applies an administrator-approved role change.
func (c *UserController) ChangeUserRole(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "User ID must be a valid UUID") {
		return
	}
	var request ChangeUserRoleRequest
	if shared.BindJSON(ec, &request) {
		return
	}
	user, err := c.userService.ChangeUserRole(ec, id, request.Role)
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error changing user role")
		return
	}
	ec.JSON(http.StatusOK, ToUserResponse(user))
}

// ChangeUserStatus applies an administrator-approved account status change.
func (c *UserController) ChangeUserStatus(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "User ID must be a valid UUID") {
		return
	}
	var request ChangeUserStatusRequest
	if shared.BindJSON(ec, &request) {
		return
	}
	user, err := c.userService.ChangeUserStatus(ec, id, request.AccountStatus)
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error changing user status")
		return
	}
	ec.JSON(http.StatusOK, ToUserResponse(user))
}

// UpdateProfile updates the authenticated user's profile fields.
func (c *UserController) UpdateProfile(ec *appcontext.GinContext) {
	var request UpdateProfileRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	user, err := c.userService.UpdateProfile(ec, request.ToServiceInput())
	if err != nil {
		if handleUserServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error updating profile")
		return
	}

	ec.JSON(http.StatusOK, ToUserResponse(user))
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
