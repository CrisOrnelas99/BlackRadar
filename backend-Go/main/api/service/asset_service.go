package service

import (
	"net"
	"strings"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
)

type AssetService interface {
	GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error)
	GetAsset(ec *appcontext.GinContext, id int64) (model.Asset, error)
	CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error)
	UpdateAsset(ec *appcontext.GinContext, id int64, asset model.Asset) (model.Asset, error)
	DeleteAsset(ec *appcontext.GinContext, id int64) (model.Asset, error)
	AssignVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error)
	RemoveVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error)
}

type assetServiceImpl struct {
	assetRepository AssetRepository
}

func NewAssetService(assetRepository AssetRepository) AssetService {
	return &assetServiceImpl{assetRepository: assetRepository}
}

func (s *assetServiceImpl) GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return nil, err
	}
	assets, err := s.assetRepository.FindAllByUser(ec, userID)
	return assets, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) GetAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.FindByIDForUser(ec, id, userID)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	if err := validateAsset(asset); err != nil {
		return model.Asset{}, err
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset.UserID = userID

	created, err := s.assetRepository.Save(ec, asset)
	return created, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) UpdateAsset(ec *appcontext.GinContext, id int64, asset model.Asset) (model.Asset, error) {
	if err := validateAsset(asset); err != nil {
		return model.Asset{}, err
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	updated, err := s.assetRepository.UpdateForUser(ec, id, userID, asset)
	return updated, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) DeleteAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.DeleteForUser(ec, id, userID)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) AssignVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.AssignVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) RemoveVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetRepository.RemoveVulnerabilityForUser(ec, assetID, userID, vulnerabilityID)
	return asset, s.translateRepositoryError(err)
}

func (s *assetServiceImpl) translateRepositoryError(err error) error {
	return translateRepositoryError(err)
}

func validateAsset(asset model.Asset) error {
	if strings.TrimSpace(asset.Name) == "" ||
		strings.TrimSpace(asset.Type) == "" ||
		strings.TrimSpace(asset.Owner) == "" ||
		strings.TrimSpace(asset.Criticality) == "" {
		return ErrInvalidRequestData
	}

	if ip := net.ParseIP(asset.IPAddress); ip == nil || ip.To4() == nil {
		return ErrInvalidRequestData
	}

	return nil
}

func authenticatedUserID(ec *appcontext.GinContext) (int64, error) {
	if ec == nil || ec.UserID() <= 0 {
		return 0, ErrForbidden
	}
	return ec.UserID(), nil
}
