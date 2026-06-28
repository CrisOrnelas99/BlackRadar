// Package security provides backend authorization helpers for role-based access control.
package security

import "secureops/backend-go/api/model"

// IsAdmin reports whether the supplied role has full administrative access.
func IsAdmin(role string) bool {
	return role == model.RoleAdmin
}

// CanManageVulnerabilities reports whether the supplied role can manage vulnerabilities.
func CanManageVulnerabilities(role string) bool {
	return role == model.RoleAdmin
}
