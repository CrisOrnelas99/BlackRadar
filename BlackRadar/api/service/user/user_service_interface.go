/*
Package service interface defines the user service contract consumed by
controllers.
*/
package service

import (
	"blackradar/api/common/pagination"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type UserService interface {
	/*
		ListUsers retrieves the accounts available to the administrator user-
		management workflow.

		Implementations should return active and deactivated accounts in the
		repository's stable order and must leave response-field filtering to the
		controller's safe user DTO mapping. Password hashes, login backoff state,
		refresh-session data, and other authentication secrets must not be exposed
		through this contract's API response.

		Repository failures should be translated into the service's dependency
		error category rather than returned as database-specific errors.
	*/
	ListUsers(ec *appcontext.GinContext, query model.UserListQuery) (pagination.Page[model.User], error)

	/*
		GetUserForManagement retrieves one account for the administrator user-
		management detail view.

		Implementations should allow the repository to return either active or
		deactivated accounts, preserve ownership of authorization decisions in the
		protected administrator workflow, and return the account for safe mapping
		by the controller. Password hashes, login backoff state, refresh sessions,
		and other authentication-only fields must remain internal.

		Missing accounts and repository failures should be translated into the
		service's not-found or dependency error categories.
	*/
	GetUserForManagement(ec *appcontext.GinContext, userID string) (model.User, error)
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
		ChangeUserRole changes one account's role through an administrator workflow.

		Implementations should validate the requested role, recheck the target
		account inside the management boundary, preserve the last-active-admin
		invariant, and return the updated account for safe response mapping.
		Repository and validation failures should be translated into service-layer
		errors rather than database-specific errors.
	*/
	ChangeUserRole(ec *appcontext.GinContext, userID string, role string) (model.User, error)

	/*
		ChangeUserStatus activates or deactivates one account through an
		administrator workflow.

		Implementations should validate the requested status, preserve the
		last-active-admin invariant, revoke active sessions when an account is
		deactivated, and return the updated account for safe response mapping.
		The operation should remain atomic with related session changes and should
		translate repository failures into service-layer errors.
	*/
	ChangeUserStatus(ec *appcontext.GinContext, userID string, status string) (model.User, error)

	// UpdateProfile validates and updates only the authenticated user's profile fields.
	UpdateProfile(ec *appcontext.GinContext, request UpdateProfileInput) (model.User, error)

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
