// Package repository provides user persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"

	commondb "blackradar/api/common/db"
	commonid "blackradar/api/common/id"
	appcontext "blackradar/api/context"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
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

// dbForContext returns the request-scoped database when present, otherwise the repository database.
func (r *UserRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

// ExistsByUsername reports whether a username already exists.
func (r *UserRepository) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("username = ?", strings.TrimSpace(username)).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return count > 0, err
}

// ExistsByEmail reports whether an email address already exists.
func (r *UserRepository) ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("email = ?", strings.ToLower(strings.TrimSpace(email))).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return count > 0, err
}

// Save creates a new user record.
func (r *UserRepository) Save(ec *appcontext.GinContext, user model.User) (model.User, error) {
	if user.OrganizationID == "" || user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		return model.User{}, baserepository.ErrInvalidData
	}

	for attempt := 0; attempt < 3; attempt++ {
		if user.ID == "" || attempt > 0 {
			identifier, err := commonid.New()
			if err != nil {
				return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrCreateFailed, err)
			}
			user.ID = identifier
		}

		err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&user).Error
		if err == nil {
			return user, nil
		}

		databaseErr := commondb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, commondb.ErrUniqueViolation) && commondb.IsPrimaryKeyViolation(err) {
			continue
		}
		if errors.Is(databaseErr, commondb.ErrUniqueViolation) {
			return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrDuplicateData, databaseErr)
		}
		if errors.Is(databaseErr, commondb.ErrForeignKeyViolation) {
			return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidReference, databaseErr)
		}
		if errors.Is(databaseErr, commondb.ErrCheckConstraintViolation) {
			return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidData, databaseErr)
		}
		return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrCreateFailed, databaseErr)
	}

	return model.User{}, fmt.Errorf("%w: exhausted random id retries", baserepository.ErrCreateFailed)
}

// FindByUsernameOrEmail returns a user that matches the supplied username or email.
func (r *UserRepository) FindByUsernameOrEmail(ec *appcontext.GinContext, userOrEmail string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("username = ? OR email = ?", strings.TrimSpace(userOrEmail), strings.ToLower(strings.TrimSpace(userOrEmail))).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return user, err
}

// FindByUsername returns a user that matches the supplied username.
func (r *UserRepository) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("username = ?", strings.TrimSpace(username)).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return user, nil
}

// FindByID returns a user that matches the supplied immutable identifier.
func (r *UserRepository) FindByID(ec *appcontext.GinContext, id string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("id = ?", strings.TrimSpace(id)).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return user, nil
}

// FindByEmail returns a user that matches the supplied email.
func (r *UserRepository) FindByEmail(ec *appcontext.GinContext, email string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("email = ?", strings.ToLower(strings.TrimSpace(email))).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return user, nil
}
