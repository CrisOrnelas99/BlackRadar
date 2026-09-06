package model

import "testing"

func TestHasPermissionRejectsUnknownRole(t *testing.T) {
	if HasPermission("unknown", PermissionViewDashboard) {
		t.Fatal("expected unknown role to have no permissions")
	}
}
