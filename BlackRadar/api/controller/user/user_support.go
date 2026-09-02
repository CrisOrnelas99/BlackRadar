// Package controller support maps user service errors to HTTP responses.
package controller

import (
	"errors"
	"net/http"
	"strings"
	"time"

	shared "blackradar/api/controller/shared"
	appcontext "blackradar/api/platform/requestcontext"
	userservice "blackradar/api/service/user"
)

const (
	refreshTokenCookieName = "blackradar_refresh_token"
	refreshTokenCookiePath = "/api/auth"
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
	case errors.Is(err, userservice.ErrProtectedAdminAccount):
		return shared.HandleError(ec, http.StatusForbidden, err, "Administrator accounts cannot be changed here.")
	case errors.Is(err, userservice.ErrLastActiveAdmin):
		return shared.HandleError(ec, http.StatusConflict, err, "The last active administrator cannot be removed.")
	case errors.As(err, &conflictErr):
		return shared.HandleError(ec, http.StatusConflict, err, "User already exists.")
	case errors.Is(err, userservice.ErrLoginBackoff):
		return shared.HandleError(ec, http.StatusTooManyRequests, err, "Too many login attempts. Please try again later.")
	case errors.As(err, &unauthorizedErr):
		return shared.HandleError(ec, http.StatusUnauthorized, err, "Invalid credentials.")
	case errors.As(err, &dependencyErr):
		return shared.HandleError(ec, http.StatusBadGateway, err, "User dependency unavailable")
	case errors.As(err, &internalErr):
		return shared.HandleError(ec, http.StatusInternalServerError, err, "User service failed")
	}

	return false
}

func setRefreshTokenCookie(ec *appcontext.GinContext, result userservice.LoginResult, secure bool) {
	maxAge := int(time.Until(result.RefreshTokenExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}

	http.SetCookie(ec.Writer, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    result.RefreshToken,
		Path:     refreshTokenCookiePath,
		Expires:  result.RefreshTokenExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearRefreshTokenCookie(ec *appcontext.GinContext, secure bool) {
	http.SetCookie(ec.Writer, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    "",
		Path:     refreshTokenCookiePath,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func refreshTokenFromCookie(ec *appcontext.GinContext) (string, error) {
	cookie, err := ec.Request.Cookie(refreshTokenCookieName)
	if err != nil {
		return "", userservice.ErrInvalidRefreshToken
	}

	token := strings.TrimSpace(cookie.Value)
	if token == "" {
		return "", userservice.ErrInvalidRefreshToken
	}

	return token, nil
}
