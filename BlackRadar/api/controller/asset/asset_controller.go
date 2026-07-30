// Package controller provides HTTP handlers for asset operations.
package controller

import (
	"net/http"

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

// GetAssets returns all assets for the authenticated user.
func (c *AssetController) GetAssets(ec *appcontext.GinContext) {
	assets, err := c.assetService.GetAllAssets(ec)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving assets")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTOs(assets))
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

// CreateAsset creates a new asset for the authenticated user.
func (c *AssetController) CreateAsset(ec *appcontext.GinContext) {
	var request AssetRequest
	if shared.BindJSON(ec, &request) {
		return
	}

	var created model.Asset
	var err error
	if request.AIMode {
		created, err = c.assetService.CreateAssetFromAI(ec, request.RawText)
	} else {
		asset := request.ToDataModel()
		created, err = c.assetService.CreateAsset(ec, asset)
	}
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

// AssignVulnerabilityByCVE looks up a CVE, stores it locally if needed, and assigns it to an asset.
func (c *AssetController) AssignVulnerabilityByCVE(ec *appcontext.GinContext) {
	assetID, err := shared.ParseID(ec.Param("id"))
	if shared.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	asset, err := c.assetVulnerabilityService.AssignVulnerabilityByCVE(ec, assetID, ec.Param("cveId"))
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error assigning vulnerability from CVE")
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

	analysis, err := c.assetMatchService.PreviewAssetMatch(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		shared.HandleError(ec, http.StatusInternalServerError, err, "Error previewing asset CPE match")
		return
	}

	ec.JSON(http.StatusOK, ToAssetMatchPreviewResponseDTO(analysis))
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
