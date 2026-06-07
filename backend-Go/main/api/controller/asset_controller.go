package controller

import (
	"errors"
	"net/http"
	"strconv"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/controller/controller_utils"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/service"
)

type AssetController struct{}

func NewAssetController() *AssetController {
	return &AssetController{}
}

func (c *AssetController) GetAssets(ec *appcontext.EchoContext) {
	assetService := service.GetAssetServiceFromEchoContext(ec)
	assets, err := assetService.GetAllAssets(ec)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error retrieving assets") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving assets")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTOs(assets))
}

func (c *AssetController) GetAsset(ec *appcontext.EchoContext) {
	id, err := parseID(ec.Param("id"))
	if controller_utils.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	assetService := service.GetAssetServiceFromEchoContext(ec)
	asset, err := assetService.GetAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error retrieving asset") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error retrieving asset")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(asset))
}

func (c *AssetController) CreateAsset(ec *appcontext.EchoContext) {
	var request model.AssetRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		controller_utils.HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	asset := request.ToDataModel()

	assetService := service.GetAssetServiceFromEchoContext(ec)
	created, err := assetService.CreateAsset(ec, asset)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error creating asset") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error creating asset")
		return
	}

	ec.JSON(http.StatusCreated, ToAssetResponseDTO(created))
}

func (c *AssetController) UpdateAsset(ec *appcontext.EchoContext) {
	id, err := parseID(ec.Param("id"))
	if controller_utils.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	var request model.AssetRequest
	if err := ec.ShouldBindJSON(&request); err != nil {
		controller_utils.HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	asset := request.ToDataModel()

	assetService := service.GetAssetServiceFromEchoContext(ec)
	updated, err := assetService.UpdateAsset(ec, id, asset)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error updating asset") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error updating asset")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(updated))
}

func (c *AssetController) DeleteAsset(ec *appcontext.EchoContext) {
	id, err := parseID(ec.Param("id"))
	if controller_utils.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	assetService := service.GetAssetServiceFromEchoContext(ec)
	_, err = assetService.DeleteAsset(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error deleting asset") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error deleting asset")
		return
	}

	ec.JSON(http.StatusOK, nil)
}

func (c *AssetController) AssignVulnerability(ec *appcontext.EchoContext) {
	assetID, vulnerabilityID, ok := parsePair(ec)
	if !ok {
		controller_utils.HandleError(ec, http.StatusBadRequest, strconv.ErrSyntax, "Asset ID and vulnerability ID must be valid positive integers")
		return
	}

	assetService := service.GetAssetServiceFromEchoContext(ec)
	asset, err := assetService.AssignVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error assigning vulnerability") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error assigning vulnerability")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(asset))
}

func (c *AssetController) RemoveVulnerability(ec *appcontext.EchoContext) {
	assetID, vulnerabilityID, ok := parsePair(ec)
	if !ok {
		controller_utils.HandleError(ec, http.StatusBadRequest, strconv.ErrSyntax, "Asset ID and vulnerability ID must be valid positive integers")
		return
	}

	assetService := service.GetAssetServiceFromEchoContext(ec)
	asset, err := assetService.RemoveVulnerability(ec, assetID, vulnerabilityID)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error removing vulnerability") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error removing vulnerability")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(asset))
}

func (c *AssetController) CalculateRisk(ec *appcontext.EchoContext) {
	id, err := parseID(ec.Param("id"))
	if controller_utils.HandleError(ec, http.StatusBadRequest, err, "Asset ID must be a valid positive integer") {
		return
	}

	assetService := service.GetAssetServiceFromEchoContext(ec)
	asset, err := assetService.CalculateRisk(ec, id)
	if err != nil {
		if handleAssetServiceError(ec, err, "Error calculating asset risk") {
			return
		}
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, "Error calculating asset risk")
		return
	}

	ec.JSON(http.StatusOK, ToAssetResponseDTO(asset))
}

func parsePair(ec *appcontext.EchoContext) (int64, int64, bool) {
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

func handleAssetServiceError(ec *appcontext.EchoContext, err error, fallbackMessage string) bool {
	var validationErr *service.ValidationError
	if errors.As(err, &validationErr) {
		controller_utils.HandleError(ec, http.StatusBadRequest, err, validationErr.Error())
		return true
	}

	var notFoundErr *service.NotFoundError
	if errors.As(err, &notFoundErr) {
		controller_utils.HandleError(ec, http.StatusNotFound, err, "Asset not found")
		return true
	}

	var unauthorizedErr *service.UnauthorizedError
	if errors.As(err, &unauthorizedErr) {
		controller_utils.HandleError(ec, http.StatusUnauthorized, err, unauthorizedErr.Error())
		return true
	}

	var forbiddenErr *service.ForbiddenError
	if errors.As(err, &forbiddenErr) {
		controller_utils.HandleError(ec, http.StatusForbidden, err, forbiddenErr.Error())
		return true
	}

	var remoteErr *service.RemoteServiceError
	if errors.As(err, &remoteErr) || errors.Is(err, service.ErrRemoteService) {
		controller_utils.HandleError(ec, http.StatusInternalServerError, err, fallbackMessage)
		return true
	}

	return false
}
