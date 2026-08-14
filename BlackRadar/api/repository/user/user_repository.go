// Package repository provides user persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"
	"time"

	commonid "blackradar/api/common/id"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	"gorm.io/gorm"
)

// UserRepository persists user records.
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a user repository backed by the supplied database.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// RefreshSessionRepository persists refresh token sessions.
type RefreshSessionRepository struct {
	db *gorm.DB
}

// NewRefreshSessionRepository creates a refresh session repository backed by the supplied database.
func NewRefreshSessionRepository(db *gorm.DB) *RefreshSessionRepository {
	return &RefreshSessionRepository{db: db}
}

// ExistsByUsername reports whether a username already exists.
func (r *UserRepository) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("username = ?", strings.TrimSpace(username)).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check username uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// ExistsByUsernameExceptID reports whether another active user uses username.
func (r *UserRepository) ExistsByUsernameExceptID(ec *appcontext.GinContext, username string, userID string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).
		Where("username = ? AND id <> ?", strings.TrimSpace(username), strings.TrimSpace(userID)).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check username uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// ExistsByEmail reports whether an email address already exists.
func (r *UserRepository) ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("email = ?", strings.ToLower(strings.TrimSpace(email))).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check email uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// ExistsByEmailExceptID reports whether another active user uses email.
func (r *UserRepository) ExistsByEmailExceptID(ec *appcontext.GinContext, email string, userID string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).
		Where("email = ? AND id <> ?", strings.ToLower(strings.TrimSpace(email)), strings.TrimSpace(userID)).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check email uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// CreateUser creates a new user record.
func (r *UserRepository) CreateUser(ec *appcontext.GinContext, user model.User) (model.User, error) {
	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		return model.User{}, ErrNotNullViolation
	}

	for attempt := 0; attempt < 3; attempt++ {
		identifier, err := commonid.New()
		if err != nil {
			return model.User{}, fmt.Errorf("%w: generate user id: %w", ErrPersistenceFailure, err)
		}
		user.ID = identifier

		err = r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&user).Error
		if err == nil {
			return user, nil
		}

		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) && platformdb.IsPrimaryKeyViolation(err) {
			continue
		}
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrUniqueViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrForeignKeyViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrCheckConstraintViolation, databaseErr)
		}
		return model.User{}, fmt.Errorf("%w: create user: %w", ErrPersistenceFailure, databaseErr)
	}

	return model.User{}, fmt.Errorf("%w: exhausted random id retries", ErrPrimaryKeyViolation)
}

// UpdateProfile updates the mutable profile fields for one active user.
func (r *UserRepository) UpdateProfile(ec *appcontext.GinContext, userID string, user model.User) (model.User, error) {
	if strings.TrimSpace(userID) == "" || user.FullName == "" || user.Username == "" || user.Email == "" {
		return model.User{}, ErrNotNullViolation
	}

	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.User{}).
		Where("id = ?", strings.TrimSpace(userID)).
		Updates(map[string]any{
			"full_name": user.FullName,
			"username":  user.Username,
			"email":     user.Email,
		})
	if result.Error != nil {
		databaseErr := platformdb.TranslateDatabaseError(result.Error)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrUniqueViolation, databaseErr)
		}
		return model.User{}, fmt.Errorf("%w: update profile: %w", ErrPersistenceFailure, databaseErr)
	}
	if result.RowsAffected == 0 {
		return model.User{}, ErrRecordNotFound
	}

	return r.FindByID(ec, userID)
}

// FindByUsername returns a user that matches the supplied username.
func (r *UserRepository) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("username = ?", strings.TrimSpace(username)).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: read user by username: %w", ErrPersistenceFailure, err)
	}
	return user, nil
}

// FindByID returns a user that matches the supplied immutable identifier.
func (r *UserRepository) FindByID(ec *appcontext.GinContext, id string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("id = ?", strings.TrimSpace(id)).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: read user by id: %w", ErrPersistenceFailure, err)
	}
	return user, nil
}

// FindByEmail returns a user that matches the supplied email.
func (r *UserRepository) FindByEmail(ec *appcontext.GinContext, email string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("email = ?", strings.ToLower(strings.TrimSpace(email))).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: read user by email: %w", ErrPersistenceFailure, err)
	}
	return user, nil
}

// UpdateLoginBackoff stores account-specific login failure state.
func (r *UserRepository) UpdateLoginBackoff(ec *appcontext.GinContext, userID string, failedCount int, lastFailedAt, lockedUntil *time.Time) error {
	if strings.TrimSpace(userID) == "" || failedCount < 0 {
		return ErrNotNullViolation
	}

	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.User{}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"failed_login_count":   failedCount,
			"last_failed_login_at": lastFailedAt,
			"locked_until":         lockedUntil,
		})
	if result.Error != nil {
		return fmt.Errorf("%w: update login backoff: %w", ErrPersistenceFailure, result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}

// CreateRefreshSession creates a new refresh session.
func (r *RefreshSessionRepository) CreateRefreshSession(ec *appcontext.GinContext, session model.RefreshSession) error {
	if session.TokenID == "" || session.UserID == "" || session.DeviceName == "" || session.ExpiresAt.IsZero() {
		return ErrNotNullViolation
	}

	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&session).Error
	if err != nil {
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return fmt.Errorf("%w: %w", ErrUniqueViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return fmt.Errorf("%w: %w", ErrForeignKeyViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return fmt.Errorf("%w: %w", ErrCheckConstraintViolation, databaseErr)
		}
		return fmt.Errorf("%w: create refresh session: %w", ErrPersistenceFailure, databaseErr)
	}
	return nil
}

// FindActiveByTokenIDForUser returns an unrevoked refresh session for a user.
func (r *RefreshSessionRepository) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
	var session model.RefreshSession
	err := activeRefreshSessionQuery(
		r.dbForContext(ec).WithContext(ec.RequestContext()),
		tokenID,
		userID,
		time.Now().UTC(),
	).
		First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.RefreshSession{}, ErrRecordNotFound
	}
	if err != nil {
		return model.RefreshSession{}, fmt.Errorf("%w: read refresh session: %w", ErrPersistenceFailure, err)
	}
	return session, nil
}

// RevokeByTokenIDForUser marks the specified refresh session revoked.
func (r *RefreshSessionRepository) RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) error {
	now := time.Now().UTC()
	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.RefreshSession{}).
		Where("token_id = ? AND user_id = ? AND revoked_at IS NULL", tokenID, userID).
		Update("revoked_at", &now)
	if result.Error != nil {
		err := result.Error
		return fmt.Errorf("%w: revoke refresh session: %w", ErrPersistenceFailure, err)
	}
	if result.RowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}

// RevokeActiveSessionsForUser marks every active refresh session for a user revoked.
func (r *RefreshSessionRepository) RevokeActiveSessionsForUser(ec *appcontext.GinContext, userID string) error {
	now := time.Now().UTC()
	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.RefreshSession{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now)
	if result.Error != nil {
		return fmt.Errorf("%w: revoke refresh sessions: %w", ErrPersistenceFailure, result.Error)
	}
	return nil
}
