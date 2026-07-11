// Package dto defines request and response data transfer objects for the API.
package dto

import (
	"time"

	"blackradar/api/model"
)

// RegisterRequest contains the fields required to create a user account.
type RegisterRequest struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
	Password     string `json:"password"`
}

// LoginRequest contains the credentials used to authenticate a user.
type LoginRequest struct {
	UserOrEmail string `json:"userOrEmail"`
	Password    string `json:"password"`
}

// RefreshRequest contains the refresh token used to exchange for a new access token.
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// UserResponse exposes the user fields safe for API responses.
type UserResponse struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
}

// LoginResponse returns the issued token and the authenticated user summary.
type LoginResponse struct {
	User                  UserResponse `json:"user"`
	Token                 string       `json:"token"`
	TokenExpiresAt        time.Time    `json:"tokenExpiresAt"`
	RefreshToken          string       `json:"refreshToken"`
	RefreshTokenExpiresAt time.Time    `json:"refreshTokenExpiresAt"`
}

// ToUserResponse converts the persistence user model into a response DTO.
func ToUserResponse(user model.User, organizationName string) UserResponse {
	return UserResponse{
		ID:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Organization: organizationName,
	}
}
