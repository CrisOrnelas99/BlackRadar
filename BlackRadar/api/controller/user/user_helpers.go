package controller

import (
	"errors"
	"net/http"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	userservice "blackradar/api/service/user"
)

// handleUserServiceError maps user service error categories to HTTP responses.
func handleUserServiceError(ec *appcontext.GinContext, err error) bool {
	var validationErr *userservice.ValidationError
	var conflictErr *userservice.ConflictError
	var unauthorizedErr *userservice.UnauthorizedError
	var dependencyErr *userservice.DependencyError
	var internalErr *userservice.InternalError

	switch {
	case errors.As(err, &validationErr):
		return shared.HandleError(ec, http.StatusBadRequest, err, err.Error())
	case errors.As(err, &conflictErr):
		return shared.HandleError(ec, http.StatusConflict, err, err.Error())
	case errors.As(err, &unauthorizedErr):
		return shared.HandleError(ec, http.StatusUnauthorized, err, "Invalid credentials.")
	case errors.As(err, &dependencyErr):
		return shared.HandleError(ec, http.StatusBadGateway, err, "User dependency unavailable")
	case errors.As(err, &internalErr):
		return shared.HandleError(ec, http.StatusInternalServerError, err, "User service failed")
	}

	return false
}
