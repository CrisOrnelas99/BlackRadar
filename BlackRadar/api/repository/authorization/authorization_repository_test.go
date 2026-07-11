package authorization

import (
	"errors"
	"testing"

	baserepository "blackradar/api/repository"
)

func TestRequireAdminFromDatabaseRejectsMissingInputs(t *testing.T) {
	if err := RequireAdminFromDatabase(nil, nil); !errors.Is(err, baserepository.ErrForbidden) {
		t.Fatalf("expected forbidden for missing inputs, got %v", err)
	}
}
