// Package service defines the service contracts used by controllers and implementations.
package service

import (
	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/model"
)

// AuthService defines the operations required for authentication flows.
type AuthService interface {
	// Register creates a new user account using the supplied registration request.
	Register(ec *appcontext.GinContext, request dto.RegisterRequest) error
	// Login authenticates the user and returns a login response containing a JWT.
	Login(ec *appcontext.GinContext, request dto.LoginRequest) (dto.LoginResponse, error)
	// Refresh exchanges a refresh token for new access credentials.
	Refresh(ec *appcontext.GinContext, request dto.RefreshRequest) (dto.LoginResponse, error)
	// Logout revokes the current refresh token session.
	Logout(ec *appcontext.GinContext, request dto.RefreshRequest) error
}

// AssetService defines the operations available for managed assets.
type AssetService interface {
	// GetAllAssets returns all assets available to the current authenticated user.
	GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error)
	// GetAsset returns a single asset by ID for the current authenticated user.
	GetAsset(ec *appcontext.GinContext, id int64) (model.Asset, error)
	// CreateAsset creates a new asset record.
	CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	// UpdateAsset updates an existing asset by ID.
	UpdateAsset(ec *appcontext.GinContext, id int64, asset model.Asset) (model.Asset, error)
	// DeleteAsset removes an asset by ID.
	DeleteAsset(ec *appcontext.GinContext, id int64) (model.Asset, error)
	// AssignVulnerability attaches a vulnerability to an asset.
	AssignVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error)
	// AssignVulnerabilityByCVE looks up a CVE, stores it locally, and attaches it to an asset.
	AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID int64, cveID string) (model.Asset, error)
	// RemoveVulnerability detaches a vulnerability from an asset.
	RemoveVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error)
}

// VulnerabilityService defines the operations available for vulnerability management.
type VulnerabilityService interface {
	// GetAllVulnerabilities returns all vulnerabilities available to the current authenticated user.
	GetAllVulnerabilities(ec *appcontext.GinContext) ([]model.Vulnerability, error)
	// GetVulnerability returns a single vulnerability by ID for the current authenticated user.
	GetVulnerability(ec *appcontext.GinContext, id int64) (model.Vulnerability, error)
	// CreateVulnerability creates a new vulnerability record.
	CreateVulnerability(ec *appcontext.GinContext, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// UpdateVulnerability updates an existing vulnerability by ID.
	UpdateVulnerability(ec *appcontext.GinContext, id int64, vulnerability model.Vulnerability) (model.Vulnerability, error)
	// DeleteVulnerability removes a vulnerability by ID.
	DeleteVulnerability(ec *appcontext.GinContext, id int64) (model.Vulnerability, error)
}

// NVDLookupService defines read-only CVE lookup operations backed by NVD data.
type NVDLookupService interface {
	// LookupCVE returns official NVD details for a single CVE ID.
	LookupCVE(ec *appcontext.GinContext, cveID string) (dto.CVELookupResponse, error)
}
