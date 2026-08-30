// Package controller provides HTTP handlers for asset operations.
package controller

import (
	"net/http"

	"blackradar/api/common/pagination"
	shared "blackradar/api/controller/shared"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	assetservice "blackradar/api/service/asset"
	assetmatchservice "blackradar/api/service/asset_match"
	assetvulnerabilityservice "blackradar/api/service/asset_vulnerability"
)

// AssetController handles asset-related HTTP requests.
type AssetController struct {
	assetService              assetservice.AssetService
	assetVulnerabilityService assetvulnerabilityservice.AssetVulnerabilityService
	assetMatchService         assetmatchservice.AssetMatchService
}

// NewAssetController creates a new AssetController.
func NewAssetController(assetService assetservice.AssetService, assetVulnerabilityService assetvulnerabilityservice.AssetVulnerabilityService, assetMatchService assetmatchservice.AssetMatchService) *AssetController {
	return &AssetController{
		assetService:              assetService,
		assetVulnerabilityService: assetVulnerabilityService,
		assetMatchService:         assetMatchService,
	}
}

// GetAssets returns one page of assets for the authenticated user.
func (c *AssetController) GetAssets(ec *appcontext.GinContext) {
	query := model.AssetListQuery{Pagination: pagination.Request{Page: 1}}
	if err := ec.ShouldBindQuery(&query); err != nil {
		shared.HandleError(ec, http.StatusBadRequest, err, "Invalid asset list parameters")
		return
	}
	assets, err := c.assetService.GetAssetPage(ec, query)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving assets")
		return
	}

	ec.JSON(http.StatusOK, ToAssetPageResponseDTO(assets))
}

// GetAssetSummary returns dashboard aggregate counts for the authenticated user.
func (c *AssetController) GetAssetSummary(ec *appcontext.GinContext) {
	summary, err := c.assetService.GetAssetSummary(ec)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving asset summary")
		return
	}
	ec.JSON(http.StatusOK, ToAssetSummaryResponseDTO(summary))
}

// GetAsset returns a single asset by ID.
func (c *AssetController) GetAsset(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	asset, err := c.assetService.GetAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving asset")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(asset))
}

// GetAssetVulnerabilities returns the vulnerabilities attached to one owned asset.
func (c *AssetController) GetAssetVulnerabilities(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	asset, err := c.assetService.GetAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving asset vulnerabilities")
		return
	}
	vulnerabilities, err := c.assetService.GetAssetVulnerabilities(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving asset vulnerabilities")
		return
	}
	asset.Vulnerabilities = vulnerabilities

	ec.JSON(http.StatusOK, ToAssetWithVulnerabilitiesResponseDTO(asset))
}

// CreateAsset creates a new asset for the authenticated user.
func (c *AssetController) CreateAsset(ec *appcontext.GinContext) {
	var request AssetRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	asset := request.ToDataModel()
	created, err := c.assetService.CreateAsset(ec, asset)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error creating asset")
		return
	}

	ec.JSON(http.StatusCreated, ToAssetResponseDTO(created))
}

// UpdateAsset updates an existing asset by ID.
func (c *AssetController) UpdateAsset(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	var request AssetRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	asset := request.ToDataModel()

	updated, err := c.assetService.UpdateAsset(ec, id, asset)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error updating asset")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(updated))
}

// DeleteAsset removes an asset by ID.
func (c *AssetController) DeleteAsset(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	_, err = c.assetService.DeleteAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error deleting asset")
		return
	}

	ec.JSON(http.StatusOK, nil)
}

// AssignVulnerability attaches a vulnerability to an asset.
func (c *AssetController) AssignVulnerability(ec *appcontext.GinContext) {
	assetID, vulnerabilityID, ok := shared.ParsePair(ec)
	if !ok {
		shared.HandleError(ec, http.StatusBadRequest, shared.ErrInvalidIdentifier, "Asset ID and vulnerability ID must be valid UUIDs")
		return
	}

	asset, err := c.assetVulnerabilityService.AssignVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error assigning vulnerability")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(asset))
}

// RemoveVulnerability removes a vulnerability association from an asset.
func (c *AssetController) RemoveVulnerability(ec *appcontext.GinContext) {
	assetID, vulnerabilityID, ok := shared.ParsePair(ec)
	if !ok {
		shared.HandleError(ec, http.StatusBadRequest, shared.ErrInvalidIdentifier, "Asset ID and vulnerability ID must be valid UUIDs")
		return
	}

	asset, err := c.assetVulnerabilityService.RemoveVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error removing vulnerability")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(asset))
}

// PreviewAssetCPEMatch normalizes saved asset fields and returns ranked NVD candidates without persistence.
func (c *AssetController) PreviewAssetCPEMatch(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	var request PreviewAssetMatchRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	preview, err := c.assetMatchService.PreviewAssetMatch(ec, id, request.SelectedCPE)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error previewing asset CPE match")
		return
	}

	ec.JSON(http.StatusOK, ToAssetMatchPreviewResponseDTO(preview))
}

// ApplyAssetCPEMatch attaches NVD vulnerabilities after an administrator approves a CPE in the request body.
func (c *AssetController) ApplyAssetCPEMatch(ec *appcontext.GinContext) {
	id, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	var request ApplyAssetMatchRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	asset, err := c.assetMatchService.ApplyApprovedCPEMatch(ec, id, request.SelectedCPE)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error applying approved asset CPE match")
		return
	}

	ec.JSON(http.StatusOK, ToAssetMatchResponseDTO(asset))
}
