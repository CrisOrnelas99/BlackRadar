// Package controller provides HTTP handlers for asset operations.
package controller

import (
	"errors"
	"net/http"
	"strconv"

	appcontext "secureops/backend-go/api/context"
	basecontroller "secureops/backend-go/api/controller"
	"secureops/backend-go/api/dto"
	baseservice "secureops/backend-go/api/service"
)

// AssetController handles asset-related HTTP requests.
type AssetController struct {
	assetService baseservice.AssetService
}

// NewAssetController creates a new AssetController.
func NewAssetController(assetService baseservice.AssetService) *AssetController {
	return &AssetController{assetService: assetService}
}

// GetAssets returns all assets for the authenticated user.
func (c *AssetController) GetAssets(ec *appcontext.GinContext) {
	assets, err := c.assetService.GetAllAssets(ec)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error retrieving assets") {
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
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	asset, err := c.assetService.GetAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error retrieving asset") {
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

	asset := request.ToDataModel()

	created, err := c.assetService.CreateAsset(ec, asset)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error creating asset") {
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
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	var request dto.AssetRequest
	if basecontroller.BindJSON(ec, &request) {
		return
	}

	asset := request.ToDataModel()

	updated, err := c.assetService.UpdateAsset(ec, id, asset)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error updating asset") {
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
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	_, err = c.assetService.DeleteAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error deleting asset") {
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
		basecontroller.HandleError(ec, http.StatusBadRequest, strconv.ErrSyntax, "Asset ID and vulnerability ID must be valid positive integers")
		return
	}

	asset, err := c.assetService.AssignVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error assigning vulnerability") {
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
	if basecontroller.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	asset, err := c.assetService.AssignVulnerabilityByCVE(ec, assetID, ec.Param("cveId"))
	if err != nil {
		if handleAssetServiceError(ec, err, "Error assigning vulnerability from CVE") {
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
		basecontroller.HandleError(ec, http.StatusBadRequest, strconv.ErrSyntax, "Asset ID and vulnerability ID must be valid positive integers")
		return
	}

	asset, err := c.assetService.RemoveVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error removing vulnerability") {
			return
		}
		basecontroller.HandleError(ec, http.StatusInternalServerError, err, "Error removing vulnerability")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

// handleAssetServiceError maps asset service sentinels to HTTP responses.
func handleAssetServiceError(ec *appcontext.GinContext, err error, fallbackMessage string) bool {
	var serviceErr *baseservice.ServiceError
	if errors.As(err, &serviceErr) {
		if errors.Is(err, baseservice.ErrInvalidRequestData) {
			basecontroller.HandleError(ec, http.StatusBadRequest, err, baseservice.ErrInvalidRequestData.Error())
			return true
		}
		if errors.Is(err, baseservice.ErrConflict) {
			basecontroller.HandleError(ec, http.StatusConflict, err, baseservice.ErrConflict.Error())
			return true
		}
		if errors.Is(err, baseservice.ErrNotFound) {
			basecontroller.HandleError(ec, http.StatusNotFound, err, "Asset not found")
			return true
		}
		if errors.Is(err, baseservice.ErrInvalidCredentials) {
			basecontroller.HandleError(ec, http.StatusUnauthorized, err, baseservice.ErrInvalidCredentials.Error())
			return true
		}
		if errors.Is(err, baseservice.ErrForbidden) {
			basecontroller.HandleError(ec, http.StatusForbidden, err, baseservice.ErrForbidden.Error())
			return true
		}
	}

	return false
}
