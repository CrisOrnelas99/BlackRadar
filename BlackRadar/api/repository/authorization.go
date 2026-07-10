// Package repository defines shared persistence-layer authorization checks.
package repository

import (
	appcontext "blackradar/api/context"
	"blackradar/api/model"

	"gorm.io/gorm"
)

// RequireAdminFromDatabase verifies the current request user is still an active admin in PostgreSQL.
func RequireAdminFromDatabase(ec *appcontext.GinContext, db *gorm.DB) error {
	if ec == nil || db == nil || ec.UserID() == "" || ec.OrganizationID() == "" {
		return ErrForbidden
	}

	var user model.User
	err := db.WithContext(ec.RequestContext()).
		Where("id = ? AND organization_id = ?", ec.UserID(), ec.OrganizationID()).
		First(&user).Error
	if err != nil {
		return ErrForbidden
	}
	if user.Role != model.RoleAdmin {
		return ErrForbidden
	}
	return nil
}
