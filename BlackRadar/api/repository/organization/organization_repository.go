// Package repository provides organization persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"

	commonid "blackradar/api/common/id"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	baserepository "blackradar/api/repository"
	"gorm.io/gorm"
)

// OrganizationRepository persists organization records.
type OrganizationRepository struct {
	db *gorm.DB
}

// NewOrganizationRepository creates an organization repository backed by the supplied database.
func NewOrganizationRepository(db *gorm.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

func (r *OrganizationRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

// FindByID returns an organization that matches the supplied identifier.
func (r *OrganizationRepository) FindByID(ec *appcontext.GinContext, id string) (model.Organization, error) {
	var organization model.Organization
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("id = ?", id).
		First(&organization).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Organization{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.Organization{}, fmt.Errorf("%w: read organization: %w", ErrPersistenceFailure, err)
	}
	return organization, nil
}

// FindByName returns an organization that matches the supplied normalized name.
func (r *OrganizationRepository) FindByName(ec *appcontext.GinContext, name string) (model.Organization, error) {
	var organization model.Organization
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("name = ?", strings.ToLower(strings.TrimSpace(name))).
		First(&organization).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Organization{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.Organization{}, fmt.Errorf("%w: read organization by name: %w", ErrPersistenceFailure, err)
	}
	return organization, nil
}

// Save persists a new organization record.
func (r *OrganizationRepository) Save(ec *appcontext.GinContext, organization model.Organization) (model.Organization, error) {
	organization.Name = strings.ToLower(strings.TrimSpace(organization.Name))
	if organization.Name == "" {
		return model.Organization{}, ErrInvalidData
	}

	for attempt := 0; attempt < 3; attempt++ {
		if organization.ID == "" || attempt > 0 {
			identifier, err := commonid.New()
			if err != nil {
				return model.Organization{}, fmt.Errorf("%w: generate organization id: %w", ErrPersistenceFailure, err)
			}
			organization.ID = identifier
		}

		err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&organization).Error
		if err == nil {
			return organization, nil
		}

		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) && platformdb.IsPrimaryKeyViolation(err) {
			continue
		}
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return model.Organization{}, fmt.Errorf("%w: %w", ErrDuplicateData, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.Organization{}, fmt.Errorf("%w: %w", ErrInvalidData, databaseErr)
		}
		return model.Organization{}, fmt.Errorf("%w: create organization: %w", ErrPersistenceFailure, databaseErr)
	}

	return model.Organization{}, fmt.Errorf("%w: exhausted random id retries", ErrPrimaryKeyConflict)
}

var _ baserepository.OrganizationRepository = (*OrganizationRepository)(nil)
