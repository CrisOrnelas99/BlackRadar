// Package repository support contains shared helpers for user persistence.
package repository

import (
	"time"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

// dbForContext returns the request-scoped database when present, otherwise the repository database.
func (r *UserRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

// dbForContext returns the request-scoped database when present, otherwise the repository database.
func (r *RefreshSessionRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

// RequirePermission verifies the current request user is still active and has a capability.
func RequirePermission(ec *appcontext.GinContext, db *gorm.DB, permission model.Permission) error {
	if ec == nil || db == nil {
		return ErrPermissionDenied
	}

	userID, err := ec.UserID()
	if err != nil {
		return ErrPermissionDenied
	}

	var user model.User
	err = db.WithContext(ec.RequestContext()).
		Where("id = ? AND account_status = ?", userID, model.AccountStatusActive).
		First(&user).Error
	if err != nil {
		return ErrPermissionDenied
	}
	if !model.HasPermission(user.Role, permission) {
		return ErrPermissionDenied
	}
	return nil
}

// activeRefreshSessionQuery scopes a query to an unrevoked, unexpired refresh session.
func activeRefreshSessionQuery(db *gorm.DB, tokenID string, userID string, now time.Time) *gorm.DB {
	return db.Where(
		"token_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?",
		tokenID,
		userID,
		now,
	)
}
