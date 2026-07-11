// Package repository provides organization persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"blackradar/api/model"
	baserepository "blackradar/api/repository"
	appcontext "blackradar/api/context"
	shared "blackradar/api/shared"
	shareddb "blackradar/api/shared/db"
	sharedid "blackradar/api/shared/id"
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
		return model.Organization{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
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
		return model.Organization{}, fmt.Errorf("%w: %w", baserepository.ErrReadFailed, err)
	}
	return organization, nil
}

// Save persists a new organization record.
func (r *OrganizationRepository) Save(ec *appcontext.GinContext, organization model.Organization) (model.Organization, error) {
	organization.Name = strings.ToLower(strings.TrimSpace(organization.Name))
	if organization.Name == "" {
		return model.Organization{}, baserepository.ErrInvalidData
	}

	for attempt := 0; attempt < 3; attempt++ {
		if organization.ID == "" || attempt > 0 {
			organization.ID = sharedid.NewRandomID()
		}

		err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&organization).Error
		if err == nil {
			return organization, nil
		}

		databaseErr := shareddb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, shared.ErrUniqueViolation) && sharedid.IsPrimaryKeyViolation(err) {
			continue
		}
		if errors.Is(databaseErr, shared.ErrUniqueViolation) {
			return model.Organization{}, fmt.Errorf("%w: %w", baserepository.ErrDuplicateData, databaseErr)
		}
		if errors.Is(databaseErr, shared.ErrCheckConstraintViolation) {
			return model.Organization{}, fmt.Errorf("%w: %w", baserepository.ErrInvalidData, databaseErr)
		}
		return model.Organization{}, fmt.Errorf("%w: %w", baserepository.ErrCreateFailed, databaseErr)
	}

	return model.Organization{}, fmt.Errorf("%w: exhausted random id retries", baserepository.ErrCreateFailed)
}

var _ baserepository.OrganizationRepository = (*OrganizationRepository)(nil)
