// Package service provides asset risk calculation application services.
package service

import (
	appcontext "blackradar/api/platform/requestcontext"
	assetriskrepository "blackradar/api/repository/asset_risk"
	auditservice "blackradar/api/service/audit"
)

// assetRiskServiceImpl implements asset risk calculation workflows.
type assetRiskServiceImpl struct {
	repository   assetriskrepository.AssetRiskRepositoryInterface
	auditService auditservice.Service
}

// WithAuditService enables durable audit events for user-triggered risk recalculations.
func (s *assetRiskServiceImpl) WithAuditService(auditService auditservice.Service) *assetRiskServiceImpl {
	s.auditService = auditService
	return s
}

// NewAssetRiskService creates an asset risk service backed by the supplied repository.
func NewAssetRiskService(repository assetriskrepository.AssetRiskRepositoryInterface) *assetRiskServiceImpl {
	return &assetRiskServiceImpl{repository: repository}
}

// RefreshAssetRisk recalculates and persists one authenticated user's asset risk level.
func (s *assetRiskServiceImpl) RefreshAssetRisk(ec *appcontext.GinContext, assetID string) error {
	if ec == nil || s.repository == nil {
		return ErrAssetRiskDependency
	}

	userID, err := ec.UserID()
	if err != nil {
		return err
	}

	vulnerabilities, err := s.repository.FindActiveVulnerabilitiesForUser(ec, assetID, userID)
	if err != nil {
		return translateAssetRiskRepositoryError(err)
	}

	riskLevel := CalculateRiskLevel(vulnerabilities)
	if err := translateAssetRiskRepositoryError(s.repository.UpdateRiskLevelForUser(
		ec,
		assetID,
		userID,
		riskLevel,
	)); err != nil {
		return err
	}
	if s.auditService == nil {
		return nil
	}
	details := "risk_level=none"
	if riskLevel != nil {
		details = "risk_level=" + *riskLevel
	}
	return s.auditService.Record(ec, auditservice.EventInput{ActorUserID: &userID, Action: "asset.risk.recalculated", ResourceType: "asset", ResourceID: &assetID, Result: auditservice.ResultSucceeded, Details: details})
}

// RefreshRisksForVulnerability recalculates risk for every asset assigned to a vulnerability.
func (s *assetRiskServiceImpl) RefreshRisksForVulnerability(ec *appcontext.GinContext, vulnerabilityID string) error {
	if ec == nil || s.repository == nil {
		return ErrAssetRiskDependency
	}

	userID, err := ec.UserID()
	if err != nil {
		return err
	}

	assetIDs, err := s.repository.FindAssignedAssetIDsForVulnerability(ec, vulnerabilityID, userID)
	if err != nil {
		return translateAssetRiskRepositoryError(err)
	}
	for _, assetID := range assetIDs {
		if err := s.RefreshAssetRisk(ec, assetID); err != nil {
			return err
		}
	}
	return nil
}
