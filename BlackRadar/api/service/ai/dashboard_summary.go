package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

const (
	dashboardSummaryAssetLimit       = 5
	dashboardSummaryFindingLimit     = 5
	dashboardSummaryDescriptionLimit = 2000
	dashboardSummaryTextLimit        = 2000
	dashboardSummaryListLimit        = 5
)

// DashboardRepositories contains the authorized data sources used to build a dashboard snapshot.
type DashboardRepositories struct {
	Assets          DashboardAssetRepository
	Vulnerabilities DashboardVulnerabilityRepository
}

// DashboardAssetRepository defines the bounded, organization-scoped reads needed by the dashboard workflow.
type DashboardAssetRepository interface {
	/*
		SummarizeByUser returns aggregate counts for active assets in userID's
		organization. The implementation must derive organization scope from the
		authenticated user relationship and return repository persistence errors.
	*/
	SummarizeByUser(ec *appcontext.GinContext, userID string) (model.AssetSummary, error)

	/*
		FindTopRiskAssetsForUser returns at most limit active assets in deterministic
		risk-priority order. Critical, high, medium, and low risk are ordered from
		highest to lowest, with asset ID as the stable tie-breaker. The implementation
		must enforce the user's organization scope and must not trust browser-provided
		ownership values.
	*/
	FindTopRiskAssetsForUser(ec *appcontext.GinContext, userID string, limit int) ([]model.Asset, error)

	/*
		FindTopVulnerabilitiesForAsset returns at most limit active vulnerabilities attached to the
		specified asset within userID's organization. Soft-deleted relationships
		and vulnerability records must be excluded. Results must be ordered by
		severity from highest to lowest with vulnerability ID as a stable tie-breaker.
	*/
	FindTopVulnerabilitiesForAsset(ec *appcontext.GinContext, assetID string, userID string, limit int) ([]model.Vulnerability, error)
}

// DashboardVulnerabilityRepository defines aggregate vulnerability reads needed by the dashboard workflow.
type DashboardVulnerabilityRepository interface {
	// CountByUser returns the active vulnerability count in userID's organization.
	CountByUser(ec *appcontext.GinContext, userID string) (int, error)

	// CountAssignedByUser returns vulnerabilities assigned to active assets in userID's organization.
	CountAssignedByUser(ec *appcontext.GinContext, userID string) (int, error)
}

// DashboardSummary is the validated advisory result returned by the dashboard AI workflow.
type DashboardSummary struct {
	Headline             string             `json:"headline"`
	OverallAssessment    string             `json:"overallAssessment"`
	Summary              string             `json:"summary"`
	PriorityFindings     []DashboardFinding `json:"priorityFindings"`
	PositiveObservations []string           `json:"positiveObservations"`
	Uncertainties        []string           `json:"uncertainties"`
}

// DashboardFinding identifies one evidence-backed risk explanation.
type DashboardFinding struct {
	Priority            int    `json:"priority"`
	AssetID             string `json:"assetId"`
	AssetName           string `json:"assetName"`
	VulnerabilityID     string `json:"vulnerabilityId"`
	CVEID               string `json:"cveId"`
	Explanation         string `json:"explanation"`
	RiskReason          string `json:"riskReason"`
	RecommendedNextStep string `json:"recommendedNextStep"`
}

type dashboardSnapshot struct {
	AssetSummary                 model.AssetSummary  `json:"assetSummary"`
	VulnerabilityCount           int                 `json:"vulnerabilityCount"`
	AssignedVulnerabilityCount   int                 `json:"assignedVulnerabilityCount"`
	UnassignedVulnerabilityCount int                 `json:"unassignedVulnerabilityCount"`
	UnaffectedAssetCount         int64               `json:"unaffectedAssetCount"`
	PriorityFindings             []dashboardEvidence `json:"priorityFindings"`
}

type dashboardEvidence struct {
	Asset         dashboardAsset         `json:"asset"`
	Vulnerability dashboardVulnerability `json:"vulnerability"`
}

type dashboardAsset struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Product     *string `json:"product,omitempty"`
	Version     *string `json:"version,omitempty"`
	Criticality string  `json:"criticality"`
	RiskLevel   *string `json:"riskLevel,omitempty"`
}

type dashboardVulnerability struct {
	ID          string `json:"id"`
	CVEID       string `json:"cveId"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// GenerateDashboardSummary builds an authorized, bounded dashboard snapshot and asks the provider for a grounded explanation. It performs no writes.
func (s *aiServiceImpl) GenerateDashboardSummary(ec *appcontext.GinContext) (DashboardSummary, error) {
	if s.dashboardRepositories.Assets == nil || s.dashboardRepositories.Vulnerabilities == nil {
		return DashboardSummary{}, ErrAIProviderUnavailable
	}

	userID, err := ec.UserID()
	if err != nil {
		return DashboardSummary{}, err
	}
	snapshot, err := s.dashboardSnapshot(ec, userID)
	if err != nil {
		return DashboardSummary{}, err
	}
	return s.generateSnapshotSummary(ec.RequestContext(), snapshot)
}

// generateSnapshotSummary validates provider references before restoring authorized record identities.
func (s *aiServiceImpl) generateSnapshotSummary(ctx context.Context, snapshot dashboardSnapshot) (DashboardSummary, error) {
	if s.textAI == nil {
		return DashboardSummary{}, ErrAIProviderUnavailable
	}

	// Numeric UUIDs can resemble phone numbers to the shared redactor. Keep
	// database identities local and give the provider distinct references instead.
	providerSnapshot := snapshot
	providerSnapshot.PriorityFindings = append([]dashboardEvidence{}, snapshot.PriorityFindings...)
	originals := make(map[string]dashboardEvidence, len(snapshot.PriorityFindings))
	for index := range providerSnapshot.PriorityFindings {
		finding := &providerSnapshot.PriorityFindings[index]
		finding.Asset.ID = fmt.Sprintf("asset-%d", index+1)
		finding.Vulnerability.ID = fmt.Sprintf("vulnerability-%d", index+1)
		originals[finding.Asset.ID+":"+finding.Vulnerability.ID] = snapshot.PriorityFindings[index]
	}
	snapshotJSON, err := json.Marshal(providerSnapshot)
	if err != nil {
		return DashboardSummary{}, ErrInvalidDashboardSummary
	}
	request := s.textGeneration.BuildDashboardSummaryRequest(snapshotJSON)
	// Validate against exactly the redacted names and CVEs the provider received.
	// Original display fields are restored only after reference validation succeeds.
	var redactedSnapshot dashboardSnapshot
	if len(request.Messages) != 2 || json.Unmarshal([]byte(request.Messages[1].Content), &redactedSnapshot) != nil {
		return DashboardSummary{}, fmt.Errorf("%w: invalid redacted snapshot", ErrInvalidDashboardSummary)
	}
	response, err := s.textAI.GenerateText(ctx, request)
	if err != nil {
		return DashboardSummary{}, errors.Join(ErrAIProviderUnavailable, err)
	}

	summary, err := parseDashboardSummary(response.Text, redactedSnapshot)
	if err != nil {
		return DashboardSummary{}, err
	}
	for index := range summary.PriorityFindings {
		finding := &summary.PriorityFindings[index]
		original, ok := originals[finding.AssetID+":"+finding.VulnerabilityID]
		if !ok {
			return DashboardSummary{}, fmt.Errorf("%w: unknown finding reference", ErrInvalidDashboardSummary)
		}
		finding.AssetID = original.Asset.ID
		finding.VulnerabilityID = original.Vulnerability.ID
		finding.AssetName = original.Asset.Name
		finding.CVEID = original.Vulnerability.CVEID
	}
	return summary, nil
}

func (s *aiServiceImpl) dashboardSnapshot(ec *appcontext.GinContext, userID string) (dashboardSnapshot, error) {
	assetSummary, err := s.dashboardRepositories.Assets.SummarizeByUser(ec, userID)
	if err != nil {
		return dashboardSnapshot{}, err
	}
	vulnerabilityCount, err := s.dashboardRepositories.Vulnerabilities.CountByUser(ec, userID)
	if err != nil {
		return dashboardSnapshot{}, err
	}
	assignedCount, err := s.dashboardRepositories.Vulnerabilities.CountAssignedByUser(ec, userID)
	if err != nil {
		return dashboardSnapshot{}, err
	}

	assets, err := s.dashboardRepositories.Assets.FindTopRiskAssetsForUser(ec, userID, dashboardSummaryAssetLimit)
	if err != nil {
		return dashboardSnapshot{}, err
	}

	evidence := make([]dashboardEvidence, 0, dashboardSummaryFindingLimit)
	for _, asset := range assets {
		assetVulnerabilities, findErr := s.dashboardRepositories.Assets.FindTopVulnerabilitiesForAsset(ec, asset.ID, userID, dashboardSummaryFindingLimit)
		if findErr != nil {
			return dashboardSnapshot{}, findErr
		}
		for _, vulnerability := range assetVulnerabilities {
			evidence = append(evidence, dashboardEvidence{
				Asset: dashboardAsset{
					ID: asset.ID, Name: asset.Name, Product: asset.Product, Version: asset.Version,
					Criticality: asset.Criticality, RiskLevel: asset.RiskLevel,
				},
				Vulnerability: dashboardVulnerability{
					ID: vulnerability.ID, CVEID: vulnerability.CVEID, Title: vulnerability.Title,
					Severity: vulnerability.Severity, Description: limitDashboardText(vulnerability.Description),
				},
			})
			if len(evidence) == dashboardSummaryFindingLimit {
				return dashboardSnapshot{AssetSummary: assetSummary, VulnerabilityCount: vulnerabilityCount, AssignedVulnerabilityCount: assignedCount, UnassignedVulnerabilityCount: vulnerabilityCount - assignedCount, UnaffectedAssetCount: assetSummary.TotalCount - assetSummary.WithVulnerabilitiesCount, PriorityFindings: evidence}, nil
			}
		}
	}

	return dashboardSnapshot{AssetSummary: assetSummary, VulnerabilityCount: vulnerabilityCount, AssignedVulnerabilityCount: assignedCount, UnassignedVulnerabilityCount: vulnerabilityCount - assignedCount, UnaffectedAssetCount: assetSummary.TotalCount - assetSummary.WithVulnerabilitiesCount, PriorityFindings: evidence}, nil
}

func parseDashboardSummary(response string, snapshot dashboardSnapshot) (DashboardSummary, error) {
	var summary DashboardSummary
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(response)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&summary); err != nil {
		return DashboardSummary{}, fmt.Errorf("%w: response JSON does not match summary schema", ErrInvalidDashboardSummary)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return DashboardSummary{}, fmt.Errorf("%w: trailing response content", ErrInvalidDashboardSummary)
	}
	if err := validateDashboardSummary(summary, snapshot); err != nil {
		return DashboardSummary{}, err
	}
	return summary, nil
}

func validateDashboardSummary(summary DashboardSummary, snapshot dashboardSnapshot) error {
	if strings.TrimSpace(summary.Headline) == "" || strings.TrimSpace(summary.Summary) == "" {
		return fmt.Errorf("%w: missing headline or summary", ErrInvalidDashboardSummary)
	}
	if len(summary.Headline) > dashboardSummaryTextLimit || len(summary.Summary) > dashboardSummaryTextLimit {
		return fmt.Errorf("%w: summary text exceeds limit", ErrInvalidDashboardSummary)
	}
	if summary.OverallAssessment != "low" && summary.OverallAssessment != "medium" && summary.OverallAssessment != "high" && summary.OverallAssessment != "critical" {
		return fmt.Errorf("%w: invalid overall assessment", ErrInvalidDashboardSummary)
	}
	if len(summary.PriorityFindings) > dashboardSummaryFindingLimit {
		return fmt.Errorf("%w: too many findings", ErrInvalidDashboardSummary)
	}
	if len(summary.PositiveObservations) > dashboardSummaryListLimit || len(summary.Uncertainties) > dashboardSummaryListLimit {
		return fmt.Errorf("%w: too many observations", ErrInvalidDashboardSummary)
	}
	for _, observation := range append(summary.PositiveObservations, summary.Uncertainties...) {
		if strings.TrimSpace(observation) == "" || len(observation) > dashboardSummaryTextLimit {
			return fmt.Errorf("%w: invalid observation length", ErrInvalidDashboardSummary)
		}
	}
	validFindings := make(map[string]dashboardEvidence, len(snapshot.PriorityFindings))
	for _, finding := range snapshot.PriorityFindings {
		validFindings[finding.Asset.ID+":"+finding.Vulnerability.ID] = finding
	}
	for index, finding := range summary.PriorityFindings {
		if len(finding.AssetName) > dashboardSummaryTextLimit || len(finding.CVEID) > dashboardSummaryTextLimit || len(finding.Explanation) > dashboardSummaryTextLimit || len(finding.RiskReason) > dashboardSummaryTextLimit || len(finding.RecommendedNextStep) > dashboardSummaryTextLimit {
			return ErrInvalidDashboardSummary
		}
		if finding.Priority != index+1 {
			return fmt.Errorf("%w: invalid finding priority", ErrInvalidDashboardSummary)
		}
		evidence, ok := validFindings[finding.AssetID+":"+finding.VulnerabilityID]
		if !ok || finding.AssetName != evidence.Asset.Name || finding.CVEID != evidence.Vulnerability.CVEID {
			return fmt.Errorf("%w: finding does not match supplied evidence", ErrInvalidDashboardSummary)
		}
	}
	return nil
}

func vulnerabilitySeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func limitDashboardText(value string) string {
	if len(value) <= dashboardSummaryDescriptionLimit {
		return value
	}
	return value[:dashboardSummaryDescriptionLimit]
}
