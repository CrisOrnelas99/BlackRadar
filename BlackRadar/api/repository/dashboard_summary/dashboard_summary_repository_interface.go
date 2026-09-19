package dashboardsummary

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

// RepositoryInterface defines organization-scoped dashboard summary persistence.
type RepositoryInterface interface {
	GetLatestForUser(ec *appcontext.GinContext, userID string) (model.DashboardSummary, error)
	SaveForUser(ec *appcontext.GinContext, userID string, summary model.DashboardSummary) (model.DashboardSummary, error)
}
