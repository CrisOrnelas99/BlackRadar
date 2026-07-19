// Package repository provides user and refresh-session persistence operations.
package repository

import (
	"errors"
	"fmt"
	"time"

	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	baserepository "blackradar/api/repository"
	"gorm.io/gorm"
)

// RefreshSessionRepository persists refresh token sessions.
type RefreshSessionRepository struct {
	db *gorm.DB
}

// NewRefreshSessionRepository creates a refresh session repository backed by the supplied database.
func NewRefreshSessionRepository(db *gorm.DB) *RefreshSessionRepository {
	return &RefreshSessionRepository{db: db}
}

func (r *RefreshSessionRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

// Save creates a new refresh session.
func (r *RefreshSessionRepository) Save(ec *appcontext.GinContext, session model.RefreshSession) error {
	if session.TokenID == "" || session.UserID == "" || session.DeviceName == "" || session.ExpiresAt.IsZero() {
		return ErrInvalidData
	}

	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&session).Error
	if err != nil {
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return fmt.Errorf("%w: %w", ErrDuplicateData, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return fmt.Errorf("%w: %w", ErrInvalidReference, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return fmt.Errorf("%w: %w", ErrInvalidData, databaseErr)
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
		return model.RefreshSession{}, ErrRefreshSessionNotFound
	}
	if err != nil {
		return model.RefreshSession{}, fmt.Errorf("%w: read refresh session: %w", ErrPersistenceFailure, err)
	}
	return session, nil
}

func activeRefreshSessionQuery(db *gorm.DB, tokenID string, userID string, now time.Time) *gorm.DB {
	return db.Where(
		"token_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?",
		tokenID,
		userID,
		now,
	)
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
		return ErrRefreshSessionNotFound
	}
	return nil
}

var _ baserepository.RefreshSessionRepository = (*RefreshSessionRepository)(nil)
