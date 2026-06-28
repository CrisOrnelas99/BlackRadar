// Package repository defines persistence contracts used by the service layer.
package repository

import (
	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
)

// UserRepository defines persistence operations for user accounts.
type UserRepository interface {
	// ExistsByUsername checks whether a username is already registered.
	ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error)
	// ExistsByEmail checks whether an email address is already registered.
	ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error)
	// Save persists a new user record.
	Save(ec *appcontext.GinContext, user model.User) error
	// FindByUsernameOrEmail returns a user by username or email.
	FindByUsernameOrEmail(ec *appcontext.GinContext, userOrEmail string) (model.User, error)
	// FindByUsername returns a user by username.
	FindByUsername(ec *appcontext.GinContext, username string) (model.User, error)
	// FindByEmail returns a user by email.
	FindByEmail(ec *appcontext.GinContext, email string) (model.User, error)
}

// RefreshSessionRepository defines persistence operations for refresh token sessions.
type RefreshSessionRepository interface {
	// Save persists a new refresh session.
	Save(ec *appcontext.GinContext, session model.RefreshSession) error
	// FindActiveByTokenIDForUser returns an active refresh session for a user.
	FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID int64) (model.RefreshSession, error)
	// RevokeByTokenIDForUser marks a refresh session as revoked.
	RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID int64) error
}

// AssetRepository defines persistence operations for asset records.
type AssetRepository interface {
	// FindAllByUser returns all assets belonging to a user.
	FindAllByUser(ec *appcontext.GinContext, userID int64) ([]model.Asset, error)
	// FindByIDForUser returns a specific asset for a user.
	FindByIDForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Asset, error)
	// Save persists a new asset.
	Save(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	// UpdateForUser updates an existing asset for a user.
	UpdateForUser(ec *appcontext.GinContext, id int64, userID int64, asset model.Asset) (model.Asset, error)
	// DeleteForUser deletes a user's asset.
	DeleteForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Asset, error)
	// AssignVulnerabilityForUser associates a vulnerability with a user's asset.
	AssignVulnerabilityForUser(ec *appcontext.GinContext, assetID int64, userID int64, vulnerabilityID int64) (model.Asset, error)
	// RemoveVulnerabilityForUser disassociates a vulnerability from a user's asset.
	RemoveVulnerabilityForUser(ec *appcontext.GinContext, assetID int64, userID int64, vulnerabilityID int64) (model.Asset, error)
}

// VulnerabilityRepository defines persistence operations for vulnerability records.
type VulnerabilityRepository interface {
	// FindAllByUser returns all vulnerabilities owned by a user.
	FindAllByUser(ec *appcontext.GinContext, userID int64) ([]model.Vulnerability, error)
	// FindByIDForUser returns a specific vulnerability for a user.
	FindByIDForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Vulnerability, error)
	// ExistsByCVEIDForUser checks whether a vulnerability CVE ID exists for a user.
	ExistsByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID int64) (bool, error)
	// ExistsByCVEIDExcludingIDForUser checks whether a CVE ID exists for a user excluding a specific record.
	ExistsByCVEIDExcludingIDForUser(ec *appcontext.GinContext, cveID string, id int64, userID int64) (bool, error)
	// FindByCVEIDForUser returns a vulnerability by CVE ID for a user.
	FindByCVEIDForUser(ec *appcontext.GinContext, cveID string, userID int64) (model.Vulnerability, error)
	// Save persists a new vulnerability.
	Save(ec *appcontext.GinContext, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// UpdateForUser updates an existing vulnerability for a user.
	UpdateForUser(ec *appcontext.GinContext, id int64, userID int64, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// DeleteForUser deletes a vulnerability for a user.
	DeleteForUser(ec *appcontext.GinContext, id int64, userID int64) (model.Vulnerability, error)
}
