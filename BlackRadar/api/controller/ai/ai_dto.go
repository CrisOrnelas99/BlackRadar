// Package controller dto defines AI request and response contracts.
package controller

import aiservice "blackradar/api/service/ai"

// AIDashboardSummaryResponse exposes a validated dashboard risk explanation.
type AIDashboardSummaryResponse struct {
	Headline             string               `json:"headline"`
	OverallAssessment    string               `json:"overallAssessment"`
	Summary              string               `json:"summary"`
	PriorityFindings     []AIDashboardFinding `json:"priorityFindings"`
	PositiveObservations []string             `json:"positiveObservations"`
	Uncertainties        []string             `json:"uncertainties"`
}

// AIDashboardFinding exposes one validated dashboard risk finding.
type AIDashboardFinding struct {
	Priority            int    `json:"priority"`
	AssetID             string `json:"assetId"`
	AssetName           string `json:"assetName"`
	VulnerabilityID     string `json:"vulnerabilityId"`
	CVEID               string `json:"cveId"`
	Explanation         string `json:"explanation"`
	RiskReason          string `json:"riskReason"`
	RecommendedNextStep string `json:"recommendedNextStep"`
}

// ToAIDashboardSummaryResponse converts a validated service result into the public API contract.
func ToAIDashboardSummaryResponse(summary aiservice.DashboardSummary) AIDashboardSummaryResponse {
	findings := make([]AIDashboardFinding, 0, len(summary.PriorityFindings))
	for _, finding := range summary.PriorityFindings {
		findings = append(findings, AIDashboardFinding{
			Priority: finding.Priority, AssetID: finding.AssetID, AssetName: finding.AssetName,
			VulnerabilityID: finding.VulnerabilityID, CVEID: finding.CVEID,
			Explanation: finding.Explanation, RiskReason: finding.RiskReason,
			RecommendedNextStep: finding.RecommendedNextStep,
		})
	}
	return AIDashboardSummaryResponse{
		Headline: summary.Headline, OverallAssessment: summary.OverallAssessment, Summary: summary.Summary,
		PriorityFindings: findings, PositiveObservations: summary.PositiveObservations,
		Uncertainties: summary.Uncertainties,
	}
}
