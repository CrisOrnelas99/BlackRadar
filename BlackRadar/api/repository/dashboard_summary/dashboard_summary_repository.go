// Package dashboardsummary persists the latest validated dashboard AI summary.
package dashboardsummary

import (
	"errors"
	"fmt"
	"strings"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Repository persists organization-scoped dashboard summaries.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a dashboard summary repository backed by the supplied database.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// GetLatestForUser returns the current summary for the authenticated user's organization.
func (r *Repository) GetLatestForUser(ec *appcontext.GinContext, userID string) (model.DashboardSummary, error) {
	if r == nil || r.db == nil || strings.TrimSpace(userID) == "" {
		return model.DashboardSummary{}, ErrPersistenceError
	}

	var summary model.DashboardSummary
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Where("organization_id = (SELECT organization_id FROM users WHERE id = ? AND account_status = ?)", userID, model.AccountStatusActive).
		First(&summary).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.DashboardSummary{}, ErrRecordNotFound
	}
	if err != nil {
		return model.DashboardSummary{}, fmt.Errorf("%w: read latest summary: %w", ErrPersistenceError, err)
	}
	return summary, nil
}

// SaveForUser replaces the current summary for the authenticated user's organization.
func (r *Repository) SaveForUser(ec *appcontext.GinContext, userID string, summary model.DashboardSummary) (model.DashboardSummary, error) {
	if r == nil || r.db == nil || strings.TrimSpace(userID) == "" || summary.SummaryPayload == "" || summary.GeneratedAt.IsZero() || summary.GeneratedByUserID == "" {
		return model.DashboardSummary{}, ErrPersistenceError
	}

	var organization struct {
		OrganizationID string
	}
	if err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.User{}).
		Select("organization_id").
		Where("id = ? AND account_status = ?", userID, model.AccountStatusActive).
		First(&organization).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.DashboardSummary{}, ErrRecordNotFound
		}
		return model.DashboardSummary{}, fmt.Errorf("%w: read summary organization: %w", ErrPersistenceError, err)
	}

	summary.OrganizationID = organization.OrganizationID
	if err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "organization_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"summary_payload", "generated_at", "generated_by_user_id", "updated_at",
			}),
		}).
		Create(&summary).Error; err != nil {
		return model.DashboardSummary{}, fmt.Errorf("%w: save summary: %w", ErrPersistenceError, err)
	}

	return r.GetLatestForUser(ec, userID)
}

func (r *Repository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

var _ RepositoryInterface = (*Repository)(nil)
