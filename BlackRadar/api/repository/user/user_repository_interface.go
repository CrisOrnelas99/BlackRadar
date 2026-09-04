/*
Package repository interface defines user and refresh-session persistence
contracts consumed by authentication services.
*/
package repository

import (
	"time"

	"blackradar/api/common/pagination"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type UserRepositoryInterface interface {
	/*
		ListUsers returns all non-soft-deleted user accounts, including both
		active and deactivated accounts, in stable creation order with the user ID
		as a deterministic tie-breaker.

		Implementations should use the request-scoped database session when one is
		available, preserve the account-status value for administrator review, and
		return only repository sentinel errors wrapped with their persistence cause
		when the query fails. Authentication-only fields remain repository data and
		must be excluded by the controller response DTO.
	*/
	ListUsers(ec *appcontext.GinContext, query model.UserListQuery) (pagination.Page[model.User], error)

	/*
		ExistsByUsername reports whether an active user already exists for
		username.

		Implementations should normalize the lookup the same way the concrete
		repository does for registration, use the request-scoped database from
		GinContext when a transaction is present, and return repository sentinel
		errors for database failures.
	*/
	ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error)

	/*
		ExistsByUsernameExceptID reports whether another active account uses
		username, excluding the supplied account ID during profile updates.

		Implementations should apply the repository's username normalization and
		active, non-soft-deleted account scope without returning account data.
		Database failures should be represented by repository sentinel errors.
	*/
	ExistsByUsernameExceptID(ec *appcontext.GinContext, username string, userID string) (bool, error)

	/*
		ExistsByEmail reports whether an active user already exists for email.

		Implementations should perform the same case-normalized lookup used by
		registration, avoid exposing any user data, and return repository
		sentinel errors for database failures.
	*/
	ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error)

	/*
		ExistsByEmailExceptID reports whether another active account uses email,
		excluding the supplied account ID during profile updates.

		Implementations should apply the same case-normalized email lookup used by
		registration and login, avoid returning account data, and preserve
		repository sentinel errors for database failures.
	*/
	ExistsByEmailExceptID(ec *appcontext.GinContext, email string, userID string) (bool, error)

	/*
		CreateUser persists the service-prepared user record and returns the
		created row.

		The service is responsible for preparing business fields such as hashed
		password values. Implementations should enforce database constraints,
		preserve generated identifiers, and wrap duplicate or persistence
		failures with repository sentinel errors.
	*/
	CreateUser(ec *appcontext.GinContext, user model.User) (model.User, error)

	/*
		UpdateRole persists a managed account's role change and records the
		administrator responsible for the update.

		Implementations should use the request-scoped transaction when available,
		update only the role and updater fields, preserve account credentials and
		status, and return the updated managed account. Privileged authorization
		must be revalidated against the current active administrator in the
		database, and persistence failures must use repository sentinel errors.
	*/
	UpdateRole(ec *appcontext.GinContext, userID string, role string, updatedByID string) (model.User, error)

	/*
		UpdateAccountStatus persists a managed account's active or deactivated
		status and records the administrator responsible for the update.

		Implementations should use the request-scoped transaction when available,
		update only the account-status and updater fields, preserve the account row
		for history, revalidate the active administrator, and return the updated
		managed account. Persistence failures must use repository sentinel errors.
	*/
	UpdateAccountStatus(ec *appcontext.GinContext, userID string, status string, updatedByID string) (model.User, error)

	/*
		CountActiveAdmins returns the number of active administrator accounts for
		last-administrator protection.

		Implementations should run within the supplied transaction and lock the
		relevant administrator rows when the database supports it, so concurrent
		role or status changes cannot remove the final active administrator.
	*/
	CountActiveAdmins(ec *appcontext.GinContext) (int64, error)

	/*
		UpdateProfile updates only the mutable profile fields for the authenticated
		account identified by the request context.

		Implementations must enforce request ownership, leave role, status,
		credentials, and security state unchanged, and return the updated account
		without exposing authentication-only fields through controller DTOs.
	*/
	UpdateProfile(ec *appcontext.GinContext, userID string, user model.User) (model.User, error)

	/*
		FindByUsername returns the active user matching username.

		Implementations must preserve soft-delete behavior so deleted users
		cannot authenticate, return ErrRecordNotFound when no active user
		matches, and wrap database failures with repository sentinel errors.
	*/
	FindByUsername(ec *appcontext.GinContext, username string) (model.User, error)

	/*
		FindByID returns the active user matching id.

		Implementations use this for token and authenticated-user validation, so
		the lookup must not return soft-deleted users. Missing users should map to
		ErrRecordNotFound and database failures should preserve their wrapped
		cause.
	*/
	FindByID(ec *appcontext.GinContext, id string) (model.User, error)

	/*
		FindByIDForManagement returns one non-soft-deleted account regardless of
		whether its account status is active or deactivated.

		Implementations should use the request-scoped database when present,
		revalidate that the requester is an active administrator, preserve the
		account's status for management decisions, and return ErrRecordNotFound
		when the account does not exist. Password hashes and other sensitive fields
		remain repository data and must be excluded from API response mapping.
	*/
	FindByIDForManagement(ec *appcontext.GinContext, id string) (model.User, error)

	/*
		FindByEmail returns the active user matching email.

		Implementations should use the same normalized email behavior used during
		registration and login, return ErrRecordNotFound when no active user
		matches, and avoid leaking whether failures came from auth logic.
	*/
	FindByEmail(ec *appcontext.GinContext, email string) (model.User, error)

	/*
		UpdateLoginBackoff stores account-specific login failure state.

		Implementations should persist the current failure count and the last
		failure or lockout timestamps on the active user row, use the request-
		scoped database when present, and return repository sentinel errors for
		persistence failures.
	*/
	UpdateLoginBackoff(ec *appcontext.GinContext, userID string, failedCount int, lastFailedAt, lockedUntil *time.Time) error
}

/*
RefreshSessionRepositoryInterface describes database operations for server-side
refresh-token sessions.
*/
type RefreshSessionRepositoryInterface interface {
	/*
		CreateRefreshSession stores the refresh-token session created during
		login or refresh.

		Implementations should persist only hashed/token-identifier session data,
		use the active transaction when present, and return repository sentinel
		errors for duplicate, constraint, or persistence failures.
	*/
	CreateRefreshSession(ec *appcontext.GinContext, session model.RefreshSession) error

	/*
		FindActiveByTokenIDForUser returns the unrevoked, unexpired refresh
		session matching tokenID and userID.

		Implementations must scope by both tokenID and userID so a token cannot be
		used across accounts, enforce active-session predicates, and return
		ErrRecordNotFound when no valid session exists.
	*/
	FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error)

	/*
		RevokeByTokenIDForUser revokes the active refresh session matching tokenID
		and userID.

		Implementations must scope the update by both values, avoid revoking
		another user's session, and return ErrRecordNotFound when there is no
		active session to revoke.
	*/
	RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) error

	/*
		RevokeActiveSessionsForUser revokes every active refresh session for the
		supplied userID.

		Implementations should scope the update to unrevoked sessions for that
		user only, use the request-scoped database when present, and return
		repository sentinel errors for database failures.
	*/
	RevokeActiveSessionsForUser(ec *appcontext.GinContext, userID string) error
}
