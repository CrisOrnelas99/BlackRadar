// Package authorization provides shared persistence-layer authorization checks.
package authorization

import (
	"blackradar/api/model"
	repository "blackradar/api/repository"
	appcontext "blackradar/api/requestContext"

	"gorm.io/gorm"
)

// RequireAdminFromDatabase verifies the current request user is still an active admin in PostgreSQL.
func RequireAdminFromDatabase(ec *appcontext.GinContext, db *gorm.DB) error {
	if ec == nil || db == nil || ec.UserID() == "" || ec.OrganizationID() == "" {
		return repository.ErrForbidden
	}

	var user model.User
	err := db.WithContext(ec.RequestContext()).
		Where("id = ? AND organization_id = ?", ec.UserID(), ec.OrganizationID()).
		First(&user).Error
	if err != nil {
		return repository.ErrForbidden
	}
	if user.Role != model.RoleAdmin {
		return repository.ErrForbidden
	}
	return nil
}
