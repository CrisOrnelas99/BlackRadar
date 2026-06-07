package dto

import "secureops/backend-go/api/model"

type AssetRequest struct {
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	IPAddress       string  `json:"ipAddress"`
	OperatingSystem *string `json:"operatingSystem"`
	Owner           string  `json:"owner"`
	Criticality     string  `json:"criticality"`
}

func (r AssetRequest) ToDataModel() model.Asset {
	return model.Asset{
		Name:            r.Name,
		Type:            r.Type,
		IPAddress:       r.IPAddress,
		OperatingSystem: r.OperatingSystem,
		Owner:           r.Owner,
		Criticality:     r.Criticality,
		RiskScore:       0,
		RiskLevel:       "Low",
	}
}

