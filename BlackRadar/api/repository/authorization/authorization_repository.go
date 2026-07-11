// Package authorization provides shared persistence-layer authorization checks.
package authorization

import (
	appcontext "blackradar/api/context"
	"blackradar/api/model"
	repository "blackradar/api/repository"

	"gorm.io/gorm"
)

// RequireAdminFromDatabase verifies the current request user is still an active admin in PostgreSQL.
func RequireAdminFromDatabase(ec *appcontext.GinContext, db *gorm.DB) error {
	if ec == nil || db == nil {
		return repository.ErrForbidden
	}

	userID, err := ec.UserID()
	if err != nil {
		return repository.ErrForbidden
	}

	organizationID, err := ec.OrganizationID()
	if err != nil {
		return repository.ErrForbidden
	}

	var user model.User
	err = db.WithContext(ec.RequestContext()).
		Where("id = ? AND organization_id = ?", userID, organizationID).
		First(&user).Error
	if err != nil {
		return repository.ErrForbidden
	}
	if user.Role != model.RoleAdmin {
		return repository.ErrForbidden
	}
	return nil
}
