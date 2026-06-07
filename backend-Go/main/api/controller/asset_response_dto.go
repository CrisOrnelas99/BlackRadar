package controller

import "secureops/backend-go/api/model"

func ToAssetResponseDTO(asset model.Asset) model.Asset {
	return asset
}

func ToAssetResponseDTOs(assets []model.Asset) []model.Asset {
	return assets
}
