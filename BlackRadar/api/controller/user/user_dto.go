// Package controller dto defines user authentication request and response contracts.
package controller

import (
	"time"

	"blackradar/api/model"
	userservice "blackradar/api/service/user"
)

// CreateUserRequest contains the fields an administrator supplies to provision a user account.
type CreateUserRequest struct {
	FullName string `json:"fullName"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest contains the credentials used to authenticate a user.
type LoginRequest struct {
	UserOrEmail string `json:"userOrEmail"`
	Password    string `json:"password"`
}

// UpdateProfileRequest contains mutable profile fields for the authenticated user.
type UpdateProfileRequest struct {
	FullName string `json:"fullName"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// UserResponse exposes the user fields safe for API responses.
type UserResponse struct {
	ID       string `json:"id"`
	FullName string `json:"fullName"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// LoginResponse returns the issued token and the authenticated user summary.
type LoginResponse struct {
	User                  UserResponse `json:"user"`
	Token                 string       `json:"token"`
	TokenExpiresAt        time.Time    `json:"tokenExpiresAt"`
	RefreshTokenExpiresAt time.Time    `json:"refreshTokenExpiresAt"`
}

// ToServiceInput converts an administrator provisioning request into service input.
func (r CreateUserRequest) ToServiceInput() userservice.CreateUserInput {
	return userservice.CreateUserInput{
		FullName: r.FullName,
		Username: r.Username,
		Email:    r.Email,
		Password: r.Password,
	}
}

// ToServiceInput converts a login request into service input.
func (r LoginRequest) ToServiceInput() userservice.LoginInput {
	return userservice.LoginInput{
		UserOrEmail: r.UserOrEmail,
		Password:    r.Password,
	}
}

// ToServiceInput converts a profile update request into service input.
func (r UpdateProfileRequest) ToServiceInput() userservice.UpdateProfileInput {
	return userservice.UpdateProfileInput{
		FullName: r.FullName,
		Username: r.Username,
		Email:    r.Email,
	}
}

// ToUserResponse converts the persistence user model into a response DTO.
func ToUserResponse(user model.User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		FullName: user.FullName,
		Username: user.Username,
		Email:    user.Email,
	}
}

// ToLoginResponse converts a login result into a safe response DTO.
func ToLoginResponse(result userservice.LoginResult) LoginResponse {
	return LoginResponse{
		User:                  ToUserResponse(result.User),
		Token:                 result.Token,
		TokenExpiresAt:        result.TokenExpiresAt,
		RefreshTokenExpiresAt: result.RefreshTokenExpiresAt,
	}
}
