package model

// Permission identifies a server-enforced application capability.
type Permission string

const (
	PermissionViewDashboard          Permission = "view_dashboard"
	PermissionManageOwnAssets        Permission = "manage_own_assets"
	PermissionViewOwnVulnerabilities Permission = "view_own_vulnerabilities"
	PermissionManageUsers            Permission = "manage_users"
	PermissionManageAdministrators   Permission = "manage_administrators"
	PermissionManageVulnerabilities  Permission = "manage_vulnerabilities"
	PermissionManageRelationships    Permission = "manage_relationships"
	PermissionApproveCPE             Permission = "approve_cpe_matching"
	PermissionViewSystemHealth       Permission = "view_system_health"
)

var allPermissions = []Permission{
	PermissionViewDashboard,
	PermissionManageOwnAssets,
	PermissionViewOwnVulnerabilities,
	PermissionManageUsers,
	PermissionManageAdministrators,
	PermissionManageVulnerabilities,
	PermissionManageRelationships,
	PermissionApproveCPE,
	PermissionViewSystemHealth,
}

// HasPermission returns the server policy for a role. Unknown roles fail closed.
func HasPermission(role string, permission Permission) bool {
	if role == RoleMaster {
		return containsPermission(allPermissions, permission)
	}
	if role == RoleAdmin {
		return permission != PermissionManageAdministrators && containsPermission(allPermissions, permission)
	}
	return permission == PermissionViewDashboard || permission == PermissionManageOwnAssets || permission == PermissionViewOwnVulnerabilities
}

// PermissionsForRole returns the safe capability list published to the client.
func PermissionsForRole(role string) []Permission {
	permissions := make([]Permission, 0, len(allPermissions))
	for _, permission := range allPermissions {
		if HasPermission(role, permission) {
			permissions = append(permissions, permission)
		}
	}
	return permissions
}

func containsPermission(permissions []Permission, wanted Permission) bool {
	for _, permission := range permissions {
		if permission == wanted {
			return true
		}
	}
	return false
}
