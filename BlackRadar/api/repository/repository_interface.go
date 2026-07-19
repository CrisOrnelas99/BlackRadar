// Package repository defines persistence contracts used by the service layer.
package repository

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
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
	// FindAllByUser returns all assets belonging to a user.
	FindAllByUser(ec *appcontext.GinContext, userID string) ([]model.Asset, error)
	// FindByIDForUser returns a specific asset for a user.
	FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)
	// ExistsBySignatureForUser checks whether an asset with the supplied normalized fields already exists for a user.
	ExistsBySignatureForUser(ec *appcontext.GinContext, asset model.Asset, userID string) (bool, error)
	// Save persists a new asset.
	Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	// UpdateForUser updates an existing asset for a user.
	UpdateForUser(ec *appcontext.GinContext, id string, userID string, asset model.Asset) (model.Asset, error)
	// UpdateMatchAnalysisForUser stores backend-generated CPE match state for an asset.
	UpdateMatchAnalysisForUser(ec *appcontext.GinContext, id string, userID string, analysis any) (model.Asset, error)
	// DeleteForUser deletes a user's asset.
	DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Asset, error)
	// AssignVulnerabilityForUser associates a vulnerability with a user's asset.
	AssignVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error)
	// RemoveVulnerabilityForUser disassociates a vulnerability from a user's asset.
	RemoveVulnerabilityForUser(ec *appcontext.GinContext, assetID string, userID string, vulnerabilityID string) (model.Asset, error)
}

// VulnerabilityRepository defines persistence operations for vulnerability records.
type VulnerabilityRepository interface {
	// FindAllByUser returns all vulnerabilities owned by a user.
	FindAllByUser(ec *appcontext.GinContext, userID string) ([]model.Vulnerability, error)
	// FindByIDForUser returns a specific vulnerability for a user.
	FindByIDForUser(ec *appcontext.GinContext, id string, userID string) (model.Vulnerability, error)
	// ExistsByCVEIDForUser checks whether a vulnerability CVE ID exists for a user.
	ExistsByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID string) (bool, error)
	// ExistsByCVEIDExcludingIDForUser checks whether a CVE ID exists for a user excluding a specific record.
	ExistsByCVEIDExcludingIDForUser(ec *appcontext.GinContext, cveID string, id string, userID string) (bool, error)
	// FindByCVEIDForUser returns a vulnerability by CVE ID for a user.
	FindByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID string) (model.Vulnerability, error)
	// Save persists a new vulnerability.
	Save(ec *appcontext.GinContext, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// UpdateForUser updates an existing vulnerability for a user.
	UpdateForUser(ec *appcontext.GinContext, id string, userID string, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// DeleteForUser deletes a vulnerability for a user.
	DeleteForUser(ec *appcontext.GinContext, id string, userID string) (model.Vulnerability, error)
}
