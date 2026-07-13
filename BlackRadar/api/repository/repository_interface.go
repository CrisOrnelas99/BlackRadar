// Package repository defines persistence contracts used by the service layer.
package repository

import (
	appcontext "blackradar/api/context"
	"blackradar/api/model"
)

// UserRepository defines persistence operations for user accounts.
type UserRepository interface {
	// ExistsByUsername checks whether a username is already registered.
	ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error)
	// ExistsByEmail checks whether an email address is already registered.
	ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error)
	// Save persists a new user record and returns the stored entity.
	Save(ec *appcontext.GinContext, user model.User) (model.User, error)
	// FindByUsernameOrEmail returns a user by username or email.
	FindByUsernameOrEmail(ec *appcontext.GinContext, userOrEmail string) (model.User, error)
	// FindByUsername returns a user by username.
	FindByUsername(ec *appcontext.GinContext, username string) (model.User, error)
	// FindByID returns a user by immutable identifier.
	FindByID(ec *appcontext.GinContext, id string) (model.User, error)
	// FindByEmail returns a user by email.
	FindByEmail(ec *appcontext.GinContext, email string) (model.User, error)
}

// OrganizationRepository defines persistence operations for tenant organizations.
type OrganizationRepository interface {
	// FindByID returns an organization by its identifier.
	FindByID(ec *appcontext.GinContext, id string) (model.Organization, error)
	// FindByName returns an organization by its normalized name.
	FindByName(ec *appcontext.GinContext, name string) (model.Organization, error)
	// Save persists a new organization record.
	Save(ec *appcontext.GinContext, organization model.Organization) (model.Organization, error)
}

// RefreshSessionRepository defines persistence operations for refresh token sessions.
type RefreshSessionRepository interface {
	// Save persists a new refresh session.
	Save(ec *appcontext.GinContext, session model.RefreshSession) error
	// FindActiveByTokenIDForUser returns an active refresh session for a user.
	FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error)
	// RevokeByTokenIDForUser marks a refresh session as revoked.
	RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) error
}

// AssetRepository defines persistence operations for asset records.
type AssetRepository interface {
	// FindAllByOrganization returns all assets belonging to an organization.
	FindAllByOrganization(ec *appcontext.GinContext, organizationID string) ([]model.Asset, error)
	// FindByIDForOrganization returns a specific asset for an organization.
	FindByIDForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Asset, error)
	// ExistsBySignatureForOrganization checks whether an asset with the supplied normalized fields already exists for an organization.
	ExistsBySignatureForOrganization(ec *appcontext.GinContext, asset model.Asset, organizationID string) (bool, error)
	// Save persists a new asset.
	Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	// UpdateForOrganization updates an existing asset for an organization.
	UpdateForOrganization(ec *appcontext.GinContext, id string, organizationID string, asset model.Asset) (model.Asset, error)
	// UpdateMatchAnalysisForOrganization stores backend-generated CPE match state for an asset.
	UpdateMatchAnalysisForOrganization(ec *appcontext.GinContext, id string, organizationID string, analysis any) (model.Asset, error)
	// DeleteForOrganization deletes an organization's asset.
	DeleteForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Asset, error)
	// AssignVulnerabilityForOrganization associates a vulnerability with an organization's asset.
	AssignVulnerabilityForOrganization(ec *appcontext.GinContext, assetID string, organizationID string, vulnerabilityID string) (model.Asset, error)
	// RemoveVulnerabilityForOrganization disassociates a vulnerability from an organization's asset.
	RemoveVulnerabilityForOrganization(ec *appcontext.GinContext, assetID string, organizationID string, vulnerabilityID string) (model.Asset, error)
}

// VulnerabilityRepository defines persistence operations for vulnerability records.
type VulnerabilityRepository interface {
	// FindAllByOrganization returns all vulnerabilities owned by an organization.
	FindAllByOrganization(ec *appcontext.GinContext, organizationID string) ([]model.Vulnerability, error)
	// FindByIDForOrganization returns a specific vulnerability for an organization.
	FindByIDForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Vulnerability, error)
	// ExistsByCVEIDForOrganization checks whether a vulnerability CVE ID exists for an organization.
	ExistsByCVEIDForOrganization(ec *appcontext.GinContext, cveID string, organizationID string) (bool, error)
	// ExistsByCVEIDExcludingIDForOrganization checks whether a CVE ID exists for an organization excluding a specific record.
	ExistsByCVEIDExcludingIDForOrganization(ec *appcontext.GinContext, cveID string, id string, organizationID string) (bool, error)
	// FindByCVEIDForOrganization returns a vulnerability by CVE ID for an organization.
	FindByCVEIDForOrganization(ec *appcontext.GinContext, cveID string, organizationID string) (model.Vulnerability, error)
	// Save persists a new vulnerability.
	Save(ec *appcontext.GinContext, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// UpdateForOrganization updates an existing vulnerability for an organization.
	UpdateForOrganization(ec *appcontext.GinContext, id string, organizationID string, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// DeleteForOrganization deletes a vulnerability for an organization.
	DeleteForOrganization(ec *appcontext.GinContext, id string, organizationID string) (model.Vulnerability, error)
}
