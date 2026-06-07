package service

import (
	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
)

type UserRepository interface {
	// ExistsByUsername reports whether a username is already stored.
	ExistsByUsername(ec *appcontext.EchoContext, username string) (bool, error)

	// ExistsByEmail reports whether an email address is already stored.
	ExistsByEmail(ec *appcontext.EchoContext, email string) (bool, error)

	// Save persists a new user record.
	Save(ec *appcontext.EchoContext, user model.User) error

	// FindByUsernameOrEmail returns the user matching a username or email.
	FindByUsernameOrEmail(ec *appcontext.EchoContext, userOrEmail string) (model.User, error)
}

type AssetRepository interface {
	// FindAll returns all stored assets ordered by ID.
	FindAll(ec *appcontext.EchoContext) ([]model.Asset, error)

	// FindByID returns one asset and its assigned vulnerabilities.
	FindByID(ec *appcontext.EchoContext, id int64) (model.Asset, error)

	// Save persists a new asset record.
	Save(ec *appcontext.EchoContext, asset model.Asset) (model.Asset, error)

	// Update changes an existing asset record.
	Update(ec *appcontext.EchoContext, id int64, asset model.Asset) (model.Asset, error)

	// Delete removes an asset record.
	Delete(ec *appcontext.EchoContext, id int64) (model.Asset, error)

	// AssignVulnerability links a vulnerability to an asset.
	AssignVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error)

	// RemoveVulnerability unlinks a vulnerability from an asset.
	RemoveVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error)

	// FindVulnerabilities returns the vulnerabilities assigned to an asset.
	FindVulnerabilities(ec *appcontext.EchoContext, assetID int64) ([]model.Vulnerability, error)

	// PersistRiskResult stores the calculated risk score and risk level for an asset.
	PersistRiskResult(ec *appcontext.EchoContext, id int64, riskResponse model.RiskCalculationResponse) (model.Asset, error)

	// EnsureAssetAndVulnerability confirms both records exist before assignment logic runs.
	EnsureAssetAndVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) error
}

type VulnerabilityRepository interface {
	// FindAll returns all stored vulnerabilities ordered by ID.
	FindAll(ec *appcontext.EchoContext) ([]model.Vulnerability, error)

	// FindByID returns one vulnerability by ID.
	FindByID(ec *appcontext.EchoContext, id int64) (model.Vulnerability, error)

	// Save persists a new vulnerability record.
	Save(ec *appcontext.EchoContext, vulnerability model.Vulnerability) (model.Vulnerability, error)

	// Update changes an existing vulnerability record.
	Update(ec *appcontext.EchoContext, id int64, vulnerability model.Vulnerability) (model.Vulnerability, error)

	// Delete removes a vulnerability record.
	Delete(ec *appcontext.EchoContext, id int64) (model.Vulnerability, error)
}
