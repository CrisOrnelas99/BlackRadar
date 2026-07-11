// Package dto defines request and response data transfer objects for the API.
package dto

import (
	"strings"

	"blackradar/api/model"
)

// AssetRequest describes the writable asset fields accepted by the API.
type AssetRequest struct {
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	OperatingSystem *string `json:"operatingSystem"`
	Vendor          *string `json:"vendor,omitempty"`
	Product         *string `json:"product,omitempty"`
	Version         *string `json:"version,omitempty"`
	DeviceModel     *string `json:"deviceModel,omitempty"`
	Owner           string  `json:"owner"`
	Criticality     string  `json:"criticality"`
	AIMode          bool    `json:"aiMode,omitempty"`
	RawText         string  `json:"rawText,omitempty"`
}

// ToDataModel converts the request into the persistence model with trimmed values.
func (r AssetRequest) ToDataModel() model.Asset {
	operatingSystem := trimOptionalString(r.OperatingSystem)

	return model.Asset{
		Name:            strings.TrimSpace(r.Name),
		Type:            strings.TrimSpace(r.Type),
		OperatingSystem: operatingSystem,
		Vendor:          trimOptionalString(r.Vendor),
		Product:         trimOptionalString(r.Product),
		Version:         trimOptionalString(r.Version),
		DeviceModel:     trimOptionalString(r.DeviceModel),
		Owner:           strings.TrimSpace(r.Owner),
		Criticality:     strings.TrimSpace(r.Criticality),
		RiskLevel:       nil,
	}
}

func trimOptionalString(value *string) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}
