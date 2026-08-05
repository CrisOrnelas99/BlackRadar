/*
Package service interface defines the user service contract consumed by
controllers.
*/
package service

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type UserService interface {
	/*
		CreateUser validates an administrator provisioning request and creates a
		standard user account.

		Implementations should normalize user input, enforce password and
		uniqueness rules, hash credentials before persistence, create only
		allowed account fields, and translate validation, conflict, or dependency
		failures into service-layer errors.
	*/
	CreateUser(ec *appcontext.GinContext, request CreateUserInput) (model.User, error)

	/*
		Login validates credentials and creates a new authenticated session.

		Implementations should avoid leaking whether username, email, or password
		failed, verify stored password hashes securely, create refresh-session
		state through the repository, and return service unauthorized or
		dependency errors when login cannot complete.
	*/
	Login(ec *appcontext.GinContext, request LoginInput) (LoginResult, error)

	/*
		Refresh validates a refresh token and issues a replacement login result.

		Implementations should parse and validate the token, verify the backing
		refresh session is active for the user, rotate server-side session state,
		and translate invalid, expired, revoked, or persistence failures into
		service-layer errors.
	*/
	Refresh(ec *appcontext.GinContext, request RefreshInput) (LoginResult, error)

	/*
		Logout revokes the refresh session represented by request.

		Implementations should validate the token, scope revocation to the token's
		user, treat invalid or missing active sessions as service errors, and
		avoid exposing sensitive token material.
	*/
	Logout(ec *appcontext.GinContext, request RefreshInput) error
}
