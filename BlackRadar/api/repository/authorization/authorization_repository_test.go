package authorization

import (
	"errors"
	"testing"
)

func TestRequireAdminFromDatabaseRejectsMissingInputs(t *testing.T) {
	if err := RequireAdminFromDatabase(nil, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden for missing inputs, got %v", err)
	}
}
