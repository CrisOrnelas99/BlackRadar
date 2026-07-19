// Package authorization provides shared persistence-layer authorization checks.
package authorization

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

// RequireAdminFromDatabase verifies the current request user is still an active admin in PostgreSQL.
func RequireAdminFromDatabase(ec *appcontext.GinContext, db *gorm.DB) error {
	if ec == nil || db == nil {
		return ErrForbidden
	}

	userID, err := ec.UserID()
	if err != nil {
		return ErrForbidden
	}

	var user model.User
	err = db.WithContext(ec.RequestContext()).
		Where("id = ?", userID).
		First(&user).Error
	if err != nil {
		return ErrForbidden
	}
	if user.Role != model.RoleAdmin {
		return ErrForbidden
	}
	return nil
}
