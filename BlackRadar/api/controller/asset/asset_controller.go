// Package controller provides HTTP handlers for asset operations.
package controller

import (
	"errors"
	"net/http"

	basecontroller "blackradar/api/controller"
	"blackradar/api/controller/dto"
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	baseservice "blackradar/api/service"
	assetservice "blackradar/api/service/asset"
)

// AssetController handles asset-related HTTP requests.
type AssetController struct {
	assetService      baseservice.AssetService
	assetMatchService baseservice.AssetMatchService
}

// NewAssetController creates a new AssetController.
func NewAssetController(assetService baseservice.AssetService, assetMatchService baseservice.AssetMatchService) *AssetController {
	return &AssetController{assetService: assetService, assetMatchService: assetMatchService}
}

// GetAssets returns all assets for the authenticated user.
func (c *AssetController) GetAssets(ec *appcontext.GinContext) {
	assets, err := c.assetService.GetAllAssets(ec)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving assets")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTOs(assets))
}

// GetAsset returns a single asset by ID.
func (c *AssetController) GetAsset(ec *appcontext.GinContext) {
	id, err := basecontroller.ParseID(ec.Param("id"))
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	asset, err := c.assetService.GetAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving asset")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

// CreateAsset creates a new asset for the authenticated user.
func (c *AssetController) CreateAsset(ec *appcontext.GinContext) {
	var request dto.AssetRequest
	if basecontroller.BindJSON(ec, &request) {
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
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error creating asset")
		return
	}

	ec.JSON(http.StatusCreated, dto.ToAssetResponseDTO(created))
}

// UpdateAsset updates an existing asset by ID.
func (c *AssetController) UpdateAsset(ec *appcontext.GinContext) {
	id, err := basecontroller.ParseID(ec.Param("id"))
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	var request dto.AssetRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	asset := request.ToDataModel()

	updated, err := c.assetService.UpdateAsset(ec, id, asset)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error updating asset")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(updated))
}

// DeleteAsset removes an asset by ID.
func (c *AssetController) DeleteAsset(ec *appcontext.GinContext) {
	id, err := basecontroller.ParseID(ec.Param("id"))
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	_, err = c.assetService.DeleteAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error deleting asset")
		return
	}

	ec.JSON(http.StatusOK, nil)
}

// AssignVulnerability attaches a vulnerability to an asset.
func (c *AssetController) AssignVulnerability(ec *appcontext.GinContext) {
	assetID, vulnerabilityID, ok := basecontroller.ParsePair(ec)
	if !ok {
		basecontroller.HandleError(ec, http.StatusBadRequest, basecontroller.ErrInvalidIdentifier, "Asset ID and vulnerability ID must be valid UUIDs")
		return
	}

	asset, err := c.assetService.AssignVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error assigning vulnerability")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

// AssignVulnerabilityByCVE looks up a CVE, stores it locally if needed, and assigns it to an asset.
func (c *AssetController) AssignVulnerabilityByCVE(ec *appcontext.GinContext) {
	assetID, err := basecontroller.ParseID(ec.Param("id"))
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	asset, err := c.assetService.AssignVulnerabilityByCVE(ec, assetID, ec.Param("cveId"))
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error assigning vulnerability from CVE")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

// RemoveVulnerability removes a vulnerability association from an asset.
func (c *AssetController) RemoveVulnerability(ec *appcontext.GinContext) {
	assetID, vulnerabilityID, ok := basecontroller.ParsePair(ec)
	if !ok {
		basecontroller.HandleError(ec, http.StatusBadRequest, basecontroller.ErrInvalidIdentifier, "Asset ID and vulnerability ID must be valid UUIDs")
		return
	}

	asset, err := c.assetService.RemoveVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error removing vulnerability")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

// MatchAssetCPE normalizes saved asset fields, ranks NVD candidates, and stores the selected match metadata.
func (c *AssetController) MatchAssetCPE(ec *appcontext.GinContext) {
	id, err := basecontroller.ParseID(ec.Param("id"))
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	asset, err := c.assetMatchService.AnalyzeAndPersistAssetMatch(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error matching asset CPE")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetMatchResponseDTO(asset))
}

// MatchAssetCPEAndAttachVulnerabilities matches a CPE, fetches NVD CVEs, and attaches them to the asset.
func (c *AssetController) MatchAssetCPEAndAttachVulnerabilities(ec *appcontext.GinContext) {
	id, err := basecontroller.ParseID(ec.Param("id"))
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid UUID") {
		return
	}

	asset, err := c.assetMatchService.AnalyzePersistAndAttachVulnerabilities(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err) {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error matching asset and assigning vulnerabilities")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetMatchResponseDTO(asset))
}

// handleAssetServiceError maps asset service sentinels to HTTP responses.
func handleAssetServiceError(ec *appcontext.GinContext, err error) bool {
	switch {
	case errors.Is(err, assetservice.ErrInvalidAssetData),
		errors.Is(err, assetservice.ErrInvalidAssetText),
		errors.Is(err, assetservice.ErrInvalidAssetCVEID):
		return basecontroller.HandleError(ec, http.StatusBadRequest, err, err.Error())
	case errors.Is(err, assetservice.ErrDuplicateAsset),
		errors.Is(err, assetservice.ErrDuplicateAssetVulnerability):
		return basecontroller.HandleError(ec, http.StatusConflict, err, err.Error())
	case errors.Is(err, assetservice.ErrAssetPermissionDenied),
		errors.Is(err, assetservice.ErrVulnerabilityManagementDenied):
		return basecontroller.HandleError(ec, http.StatusForbidden, err, err.Error())
	case errors.Is(err, assetservice.ErrAssetNotFound),
		errors.Is(err, assetservice.ErrAssetVulnerabilityNotFound):
		return basecontroller.HandleError(ec, http.StatusNotFound, err, err.Error())
	}

	return basecontroller.HandleServiceError(ec, err, basecontroller.ServiceErrorMessages{
		NotFound:        "Asset not found",
		ExternalService: "External service unavailable",
	})
}
