// Package repository provides refresh session persistence operations.
package repository

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	appcontext "blackradar/api/context"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
	"blackradar/api/utils"
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
		return baserepository.ErrInvalidData
	}

	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&session).Error
	if err != nil {
		databaseErr := utils.TranslateDatabaseError(err)
		if errors.Is(databaseErr, utils.ErrUniqueViolation) {
			return fmt.Errorf("%w: %w", baserepository.ErrDuplicateData, databaseErr)
		}
		if errors.Is(databaseErr, utils.ErrForeignKeyViolation) {
			return fmt.Errorf("%w: %w", baserepository.ErrInvalidReference, databaseErr)
		}
		if errors.Is(databaseErr, utils.ErrCheckConstraintViolation) {
			return fmt.Errorf("%w: %w", baserepository.ErrInvalidData, databaseErr)
		}
		return fmt.Errorf("%w: %w", baserepository.ErrCreateFailed, databaseErr)
	}
	return nil
}

// FindActiveByTokenIDForUser returns an unrevoked refresh session for a user.
func (r *RefreshSessionRepository) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
	var session model.RefreshSession
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("token_id = ? AND user_id = ? AND revoked_at IS NULL", tokenID, userID).
		First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.RefreshSession{}, baserepository.ErrRefreshSessionNotFound
	}
	if err != nil {
		return model.RefreshSession{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
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
		return fmt.Errorf("%w: %w", baserepository.ErrUpdateFailed, err)
	}
	if result.RowsAffected == 0 {
		return baserepository.ErrRefreshSessionNotFound
	}
	return nil
}

var _ baserepository.RefreshSessionRepository = (*RefreshSessionRepository)(nil)
