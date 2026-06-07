package controller

import (
	"errors"
	"net/http"
	"strconv"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/service"
)

type AssetController struct {
	assetService service.AssetService
}

func NewAssetController(assetService service.AssetService) *AssetController {
	return &AssetController{assetService: assetService}
}

func (c *AssetController) GetAssets(ec *appcontext.GinContext) {
	assets, err := c.assetService.GetAllAssets(ec)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error retrieving assets") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error retrieving assets")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTOs(assets))
}

func (c *AssetController) GetAsset(ec *appcontext.GinContext) {
	id, err := parseID(ec.Param("id"))
	if HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	asset, err := c.assetService.GetAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error retrieving asset") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error retrieving asset")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

func (c *AssetController) CreateAsset(ec *appcontext.GinContext) {
	var request dto.AssetRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	asset := request.ToDataModel()

	created, err := c.assetService.CreateAsset(ec, asset)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error creating asset") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error creating asset")
		return
	}

	ec.JSON(http.StatusCreated, dto.ToAssetResponseDTO(created))
}

func (c *AssetController) UpdateAsset(ec *appcontext.GinContext) {
	id, err := parseID(ec.Param("id"))
	if HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	var request dto.AssetRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	asset := request.ToDataModel()

	updated, err := c.assetService.UpdateAsset(ec, id, asset)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error updating asset") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error updating asset")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(updated))
}

func (c *AssetController) DeleteAsset(ec *appcontext.GinContext) {
	id, err := parseID(ec.Param("id"))
	if HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	_, err = c.assetService.DeleteAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error deleting asset") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error deleting asset")
		return
	}

	ec.JSON(http.StatusOK, nil)
}

func (c *AssetController) AssignVulnerability(ec *appcontext.GinContext) {
	assetID, vulnerabilityID, ok := parsePair(ec)
	if !ok {
		HandleError(ec, http.StatusBadRequest, strconv.ErrSyntax, "Asset ID and vulnerability ID must be valid positive integers")
		return
	}

	asset, err := c.assetService.AssignVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error assigning vulnerability") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error assigning vulnerability")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

func (c *AssetController) RemoveVulnerability(ec *appcontext.GinContext) {
	assetID, vulnerabilityID, ok := parsePair(ec)
	if !ok {
		HandleError(ec, http.StatusBadRequest, strconv.ErrSyntax, "Asset ID and vulnerability ID must be valid positive integers")
		return
	}

	asset, err := c.assetService.RemoveVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error removing vulnerability") {
			return
		}
		HandleError(ec, http.StatusInternalServerError, err, "Error removing vulnerability")
		return
	}

	ec.JSON(http.StatusOK, dto.ToAssetResponseDTO(asset))
}

func parsePair(ec *appcontext.GinContext) (int64, int64, bool) {
	assetID, err := parseID(ec.Param("id"))
	if err != nil {
		return 0, 0, false
	}
	vulnerabilityID, err := parseID(ec.Param("vulnerabilityId"))
	if err != nil {
		return 0, 0, false
	}
	return assetID, vulnerabilityID, true
}

func parseID(value string) (int64, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, strconv.ErrSyntax
	}
	return id, nil
}

func handleAssetServiceError(ec *appcontext.GinContext, err error, fallbackMessage string) bool {
	var validationErr *service.ValidationError
	if errors.As(err, &validationErr) {
		HandleError(ec, http.StatusBadRequest, err, validationErr.Error())
		return true
	}

	var notFoundErr *service.NotFoundError
	if errors.As(err, &notFoundErr) {
		HandleError(ec, http.StatusNotFound, err, "Asset not found")
		return true
	}

	var unauthorizedErr *service.UnauthorizedError
	if errors.As(err, &unauthorizedErr) {
		HandleError(ec, http.StatusUnauthorized, err, unauthorizedErr.Error())
		return true
	}

	var forbiddenErr *service.ForbiddenError
	if errors.As(err, &forbiddenErr) {
		HandleError(ec, http.StatusForbidden, err, forbiddenErr.Error())
		return true
	}

	return false
}
