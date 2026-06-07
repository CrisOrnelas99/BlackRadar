package repository

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/shared"
)

type AssetRepository struct {
	db *gorm.DB
}

func NewAssetRepository(db *gorm.DB) *AssetRepository {
	return &AssetRepository{db: db}
}

func GetAssetRepoFromEchoContext(ec *appcontext.EchoContext) *AssetRepository {
	if ec == nil {
		return &AssetRepository{}
	}

	if value, exists := ec.Get(appcontext.AssetRepoKey); exists {
		if repo, ok := value.(*AssetRepository); ok {
			return repo
		}
	}

	repo := &AssetRepository{}
	ec.Set(appcontext.AssetRepoKey, repo)
	return repo
}

func (r *AssetRepository) database(ec *appcontext.EchoContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

func (r *AssetRepository) FindAll(ec *appcontext.EchoContext) ([]model.Asset, error) {
	var assets []model.Asset
	err := r.database(ec).WithContext(ec.RequestContext()).Order("id").Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return assets, err
}

func (r *AssetRepository) FindByID(ec *appcontext.EchoContext, id int64) (model.Asset, error) {
	var asset model.Asset
	err := r.database(ec).WithContext(ec.RequestContext()).Preload("Vulnerabilities").First(&asset, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, ErrAssetNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return asset, err
}

func (r *AssetRepository) Save(ec *appcontext.EchoContext, asset model.Asset) (model.Asset, error) {
	if asset.Name == "" || asset.Type == "" || asset.IPAddress == "" || asset.Owner == "" || asset.Criticality == "" {
		return model.Asset{}, ErrInvalidData
	}

	err := r.database(ec).WithContext(ec.RequestContext()).Create(&asset).Error
	if err != nil {
		if shared.IsForeignKeyViolation(err) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
		}
		if shared.IsCheckConstraintViolation(err) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidData, err)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", ErrCreateFailed, err)
	}
	return asset, err
}

func (r *AssetRepository) Update(ec *appcontext.EchoContext, id int64, updates model.Asset) (model.Asset, error) {
	if updates.Name == "" || updates.Type == "" || updates.IPAddress == "" || updates.Owner == "" || updates.Criticality == "" {
		return model.Asset{}, ErrInvalidData
	}

	asset, err := r.FindByID(ec, id)
	if err != nil {
		return model.Asset{}, err
	}

	asset.Name = updates.Name
	asset.Type = updates.Type
	asset.IPAddress = updates.IPAddress
	asset.OperatingSystem = updates.OperatingSystem
	asset.Owner = updates.Owner
	asset.Criticality = updates.Criticality

	err = r.database(ec).WithContext(ec.RequestContext()).Save(&asset).Error
	if err != nil {
		if shared.IsForeignKeyViolation(err) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
		}
		if shared.IsCheckConstraintViolation(err) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidData, err)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", ErrUpdateFailed, err)
	}
	return r.FindByID(ec, id)
}

func (r *AssetRepository) Delete(ec *appcontext.EchoContext, id int64) (model.Asset, error) {
	asset, err := r.FindByID(ec, id)
	if err != nil {
		return model.Asset{}, err
	}
	err = r.database(ec).WithContext(ec.RequestContext()).Delete(&asset).Error
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", ErrDeleteFailed, err)
	}
	return asset, err
}

func (r *AssetRepository) AssignVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	asset, err := r.FindByID(ec, assetID)
	if err != nil {
		return model.Asset{}, err
	}

	var vulnerability model.Vulnerability
	err = r.database(ec).WithContext(ec.RequestContext()).First(&vulnerability, vulnerabilityID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, ErrVulnerabilityNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	for _, assigned := range asset.Vulnerabilities {
		if assigned.ID == vulnerability.ID {
			return model.Asset{}, ErrDuplicateAssignment
		}
	}

	err = r.database(ec).WithContext(ec.RequestContext()).Model(&asset).Association("Vulnerabilities").Append(&vulnerability)
	if err != nil {
		if shared.IsForeignKeyViolation(err) {
			return model.Asset{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
		}
		return model.Asset{}, fmt.Errorf("%w: %w", ErrCreateFailed, err)
	}

	return r.FindByID(ec, assetID)
}

func (r *AssetRepository) RemoveVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	asset, vulnerability, err := r.findAssetAndVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		return model.Asset{}, err
	}

	err = r.database(ec).WithContext(ec.RequestContext()).Model(&asset).Association("Vulnerabilities").Delete(&vulnerability)
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", ErrDeleteFailed, err)
	}

	return r.FindByID(ec, assetID)
}

func (r *AssetRepository) FindVulnerabilities(ec *appcontext.EchoContext, assetID int64) ([]model.Vulnerability, error) {
	asset, err := r.FindByID(ec, assetID)
	if err != nil {
		return nil, err
	}
	return asset.Vulnerabilities, nil
}

func (r *AssetRepository) PersistRiskResult(ec *appcontext.EchoContext, id int64, riskResponse model.RiskCalculationResponse) (model.Asset, error) {
	if riskResponse.RiskScore < -32768 || riskResponse.RiskScore > 32767 {
		return model.Asset{}, ErrRiskScoreOutOfRange
	}

	asset, err := r.FindByID(ec, id)
	if err != nil {
		return model.Asset{}, err
	}

	asset.RiskScore = int16(riskResponse.RiskScore)
	asset.RiskLevel = riskResponse.RiskLevel

	err = r.database(ec).WithContext(ec.RequestContext()).Save(&asset).Error
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %w", ErrUpdateFailed, err)
	}

	return r.FindByID(ec, id)
}

func (r *AssetRepository) EnsureAssetAndVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) error {
	_, _, err := r.findAssetAndVulnerability(ec, assetID, vulnerabilityID)
	return err
}

func (r *AssetRepository) findAssetAndVulnerability(ec *appcontext.EchoContext, assetID int64, vulnerabilityID int64) (model.Asset, model.Vulnerability, error) {
	asset, err := r.FindByID(ec, assetID)
	if err != nil {
		return model.Asset{}, model.Vulnerability{}, err
	}

	var vulnerability model.Vulnerability
	err = r.database(ec).WithContext(ec.RequestContext()).First(&vulnerability, vulnerabilityID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Asset{}, model.Vulnerability{}, ErrVulnerabilityNotFound
	}
	if err != nil {
		return model.Asset{}, model.Vulnerability{}, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}

	return asset, vulnerability, nil
}
