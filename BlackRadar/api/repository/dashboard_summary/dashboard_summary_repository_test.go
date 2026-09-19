package dashboardsummary

import (
	"testing"

	"blackradar/api/model"
)

func TestRepositoryRejectsInvalidSummaryInput(t *testing.T) {
	repository := &Repository{}

	if _, err := repository.GetLatestForUser(nil, ""); err != ErrPersistenceError {
		t.Fatalf("expected invalid read input error, got %v", err)
	}
	if _, err := repository.SaveForUser(nil, "", model.DashboardSummary{}); err != ErrPersistenceError {
		t.Fatalf("expected invalid write input error, got %v", err)
	}
}
