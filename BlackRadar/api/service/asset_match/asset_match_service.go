// Package asset_match provides asset CPE and CVE matching services.
package asset_match

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	nvdcpeclient "blackradar/api/external/nvd_cpe"
	nvdcveclient "blackradar/api/external/nvd_cve"
	openaiexternal "blackradar/api/external/openai"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	transactionboundary "blackradar/api/platform/transaction"
	assetmatchrepo "blackradar/api/repository/asset_match"
	assetvulnerabilityrepo "blackradar/api/repository/asset_vulnerability"
	vulnerabilityrepo "blackradar/api/repository/vulnerability"
	assetriskservice "blackradar/api/service/asset_risk"
	assetvulnerabilityservice "blackradar/api/service/asset_vulnerability"
	auditservice "blackradar/api/service/audit"
	textgenerationservice "blackradar/api/service/text_generation"
)

const (
	maxAutoAttachedCVEs          = 10
	maxKeywordFallbackSearches   = 5
	maxKeywordFallbackNVDResults = 100
	maxKeywordFallbackCandidates = 20
	minKeywordFallbackConfidence = 0.55
)

// AssetMatchAnalysis captures the backend's CPE ranking decision.
type AssetMatchAnalysis struct {
	ProductFingerprint string
	KeywordSearch      string
	SelectedCPE        string
	Confidence         float64
	ReviewStatus       string
	ReviewNotes        string
	CandidateCount     int
	Candidates         []nvdcpeclient.CPECandidate
}

// AssetFingerprint captures the normalized product signals derived from an asset.
type AssetFingerprint struct {
	Vendor          string
	Product         string
	Version         string
	OperatingSystem string
	DeviceModel     string
	AssetName       string
	AssetType       string
	Canonical       string
}

// assetMatchServiceImpl implements asset-to-CPE and CVE matching workflows.
type assetMatchServiceImpl struct {
	assetMatchRepository         assetmatchrepo.AssetMatchRepositoryInterface
	assetVulnerabilityRepository assetvulnerabilityrepo.AssetVulnerabilityRepositoryInterface
	vulnRepository               vulnerabilityrepo.VulnerabilityRepositoryInterface
	cpeSearcher                  nvdcpeclient.CPEClientInterface
	cveSearcher                  nvdcveclient.CVEClientInterface
	textAI                       openaiexternal.OpenAIClientInterface
	textGeneration               textgenerationservice.TextGenerationService
	assetRiskService             assetriskservice.AssetRiskService
	transactionRunner            transactionboundary.Runner
	now                          func() time.Time
	auditService                 auditservice.Service
}

// WithAuditService enables durable audit events for approved AI-assisted persistence.
func (s *assetMatchServiceImpl) WithAuditService(auditService auditservice.Service) *assetMatchServiceImpl {
	s.auditService = auditService
	return s
}

// NewAssetMatchService creates a backend-only asset matching service.
func NewAssetMatchService(assetMatchRepository assetmatchrepo.AssetMatchRepositoryInterface, assetVulnerabilityRepository assetvulnerabilityrepo.AssetVulnerabilityRepositoryInterface, vulnRepository vulnerabilityrepo.VulnerabilityRepositoryInterface, cpeSearcher nvdcpeclient.CPEClientInterface, cveSearcher nvdcveclient.CVEClientInterface, textAI openaiexternal.OpenAIClientInterface, riskServices ...assetriskservice.AssetRiskService) *assetMatchServiceImpl {
	service := &assetMatchServiceImpl{
		assetMatchRepository:         assetMatchRepository,
		assetVulnerabilityRepository: assetVulnerabilityRepository,
		vulnRepository:               vulnRepository,
		cpeSearcher:                  cpeSearcher,
		cveSearcher:                  cveSearcher,
		textAI:                       textAI,
		textGeneration:               textgenerationservice.NewTextGenerationService(),
		transactionRunner:            platformdb.RequestTransactionRunner{},
		now:                          time.Now,
	}
	if len(riskServices) > 0 {
		service.assetRiskService = riskServices[0]
	}
	return service
}

// nvdLookupServiceImpl adapts the NVD CVE client for controller lookups.
type nvdLookupServiceImpl struct {
	client nvdcveclient.CVEClientInterface
}

// NewNVDLookupService creates a read-only NVD lookup service.
func NewNVDLookupService(client nvdcveclient.CVEClientInterface) *nvdLookupServiceImpl {
	return &nvdLookupServiceImpl{client: client}
}

// LookupCVE validates the request and returns official NVD details for one CVE ID.
func (s *nvdLookupServiceImpl) LookupCVE(ec *appcontext.GinContext, cveID string) (nvdcveclient.CVELookupResponse, error) {
	if _, err := authenticatedUserID(ec); err != nil {
		return nvdcveclient.CVELookupResponse{}, err
	}

	normalizedCVEID := normalizeCVEID(cveID)
	if err := validateCVEID(normalizedCVEID); err != nil {
		return nvdcveclient.CVELookupResponse{}, ErrInvalidCVEID
	}
	if s.client == nil {
		return nvdcveclient.CVELookupResponse{}, ErrMatchExternalService
	}

	ctx, cancel := context.WithTimeout(ec.Request.Context(), 10*time.Second)
	defer cancel()

	response, err := s.client.LookupCVE(ctx, normalizedCVEID)
	switch {
	case err == nil:
		return response, nil
	case errors.Is(err, nvdcveclient.ErrInvalidCVEID):
		return nvdcveclient.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrInvalidCVEID, err)
	case errors.Is(err, nvdcveclient.ErrCVEIDNotFound):
		return nvdcveclient.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrCVENotFound, err)
	case errors.Is(err, nvdcveclient.ErrNVDRateLimited):
		return nvdcveclient.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrNVDLookupRateLimited, err)
	case errors.Is(err, nvdcveclient.ErrNVDUnavailable), errors.Is(err, nvdcveclient.ErrInvalidNVDResponse):
		return nvdcveclient.CVELookupResponse{}, fmt.Errorf("%w: %w", ErrMatchExternalService, err)
	default:
		return nvdcveclient.CVELookupResponse{}, fmt.Errorf("%w: %v", ErrMatchExternalService, err)
	}
}

// AnalyzeAssetMatch builds a fingerprint, fetches NVD candidates, and asks the AI layer to rank them.
func (s *assetMatchServiceImpl) AnalyzeAssetMatch(ctx context.Context, asset model.Asset, rawText string) (AssetMatchAnalysis, error) {
	if s.cpeSearcher == nil {
		return AssetMatchAnalysis{}, ErrMatchExternalService
	}

	sanitizedText := ""
	if strings.TrimSpace(rawText) != "" {
		var err error
		sanitizedText, err = sanitizeAIIngestionText(rawText)
		if err != nil {
			return AssetMatchAnalysis{
				ProductFingerprint: BuildAssetFingerprint(asset, "").Canonical,
				ReviewStatus:       model.AssetCPEReviewStatusNeedsReview,
				ReviewNotes:        "unsafe or oversized pasted content rejected",
			}, nil
		}
	}

	fingerprint := BuildAssetFingerprint(asset, sanitizedText)
	if sanitizedText != "" {
		if aiFingerprint, ok := s.normalizeFingerprintWithAI(ctx, asset, sanitizedText, fingerprint); ok {
			fingerprint = aiFingerprint
		}
	}
	keywordSearches := buildCPEKeywordSearches(fingerprint)
	if len(keywordSearches) == 0 {
		return AssetMatchAnalysis{
			ProductFingerprint: fingerprint.Canonical,
			ReviewStatus:       model.AssetCPEReviewStatusNeedsReview,
			ReviewNotes:        "insufficient fingerprint data for candidate search",
		}, nil
	}

	keywordSearch, candidates, err := s.searchCPECandidates(ctx, keywordSearches)
	if err != nil {
		return AssetMatchAnalysis{
			ProductFingerprint: fingerprint.Canonical,
			KeywordSearch:      keywordSearch,
			ReviewStatus:       model.AssetCPEReviewStatusNeedsReview,
			ReviewNotes:        "nvd candidate search failed",
		}, nil
	}
	if len(candidates) == 0 {
		return AssetMatchAnalysis{
			ProductFingerprint: fingerprint.Canonical,
			KeywordSearch:      keywordSearch,
			ReviewStatus:       model.AssetCPEReviewStatusNeedsReview,
			ReviewNotes:        "no NVD CPE candidates returned",
		}, nil
	}

	ranking, err := s.rankCandidates(ctx, fingerprint, keywordSearch, candidates)
	if err != nil {
		return AssetMatchAnalysis{
			ProductFingerprint: fingerprint.Canonical,
			KeywordSearch:      keywordSearch,
			ReviewStatus:       model.AssetCPEReviewStatusNeedsReview,
			ReviewNotes:        "ai ranking unavailable",
			CandidateCount:     len(candidates),
			Candidates:         candidates,
		}, nil
	}

	selectedCPE := normalizeCPEName(ranking.SelectedCPE)
	reviewStatus := model.AssetCPEReviewStatusNeedsReview
	reviewNotes := strings.TrimSpace(ranking.ReviewNotes)
	if selectedCPE != "" && !containsCPECandidate(candidates, selectedCPE) {
		reviewNotes = "selected cpe was not returned by the nvd candidate search"
		selectedCPE = ""
	}
	if selectedCPE != "" && ranking.Confidence >= 0.85 && isStrongFingerprint(fingerprint) {
		reviewStatus = model.AssetCPEReviewStatusAccepted
	} else if reviewNotes == "" {
		reviewNotes = "match requires review"
	}

	return AssetMatchAnalysis{
		ProductFingerprint: fingerprint.Canonical,
		KeywordSearch:      keywordSearch,
		SelectedCPE:        selectedCPE,
		Confidence:         ranking.Confidence,
		ReviewStatus:       reviewStatus,
		ReviewNotes:        reviewNotes,
		CandidateCount:     len(candidates),
		Candidates:         candidates,
	}, nil
}

// PreviewAssetMatch returns a non-persistent CPE proposal for an asset.
func (s *assetMatchServiceImpl) PreviewAssetMatch(ec *appcontext.GinContext, assetID string) (AssetMatchAnalysis, error) {
	role, err := authenticatedRole(ec)
	if err != nil {
		return AssetMatchAnalysis{}, assetvulnerabilityservice.ErrAssetPermissionDenied
	}
	if !canManageVulnerabilities(role) {
		return AssetMatchAnalysis{}, assetvulnerabilityservice.ErrVulnerabilityManagementDenied
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return AssetMatchAnalysis{}, err
	}

	asset, err := s.assetMatchRepository.FindByIDForUser(ec, assetID, userID)
	if err != nil {
		return AssetMatchAnalysis{}, translateMatchRepositoryError(err)
	}

	analysis, err := s.AnalyzeAssetMatch(ec.RequestContext(), asset, "")
	if err != nil {
		return AssetMatchAnalysis{}, err
	}
	ec.Logger().Info("asset cpe match analysis",
		"asset_id", assetID,
		"product_fingerprint", analysis.ProductFingerprint,
		"nvd_cpe_keyword_search", analysis.KeywordSearch,
		"nvd_cpe_candidate_count", analysis.CandidateCount,
		"selected_cpe", analysis.SelectedCPE,
		"review_status", analysis.ReviewStatus,
	)
	return analysis, nil
}

// ApplyApprovedCPEMatch attaches NVD vulnerabilities for an administrator-selected CPE.
func (s *assetMatchServiceImpl) ApplyApprovedCPEMatch(ec *appcontext.GinContext, assetID string, selectedCPE string) (model.Asset, error) {
	role, err := authenticatedRole(ec)
	if err != nil {
		return model.Asset{}, assetvulnerabilityservice.ErrAssetPermissionDenied
	}
	if !canManageVulnerabilities(role) {
		return model.Asset{}, assetvulnerabilityservice.ErrVulnerabilityManagementDenied
	}
	if s.assetVulnerabilityRepository == nil || s.vulnRepository == nil || s.cveSearcher == nil {
		return model.Asset{}, ErrMatchExternalService
	}

	selectedCPE = normalizeCPEName(selectedCPE)
	if !strings.HasPrefix(selectedCPE, "cpe:2.3:") {
		return model.Asset{}, ErrMatchExternalService
	}

	userID, err := authenticatedUserID(ec)
	if err != nil {
		return model.Asset{}, err
	}
	asset, err := s.assetMatchRepository.FindByIDForUser(ec, assetID, userID)
	if err != nil {
		return model.Asset{}, translateMatchRepositoryError(err)
	}

	cves, err := s.cveSearcher.SearchCVEsByCPE(ec.RequestContext(), selectedCPE, maxAutoAttachedCVEs)
	if err != nil {
		return model.Asset{}, fmt.Errorf("%w: %v", ErrMatchExternalService, err)
	}
	if len(cves) == 0 {
		return model.Asset{}, ValidationError{Message: "selected CPE has no NVD vulnerabilities"}
	}

	analysis := AssetMatchAnalysis{
		ProductFingerprint: BuildAssetFingerprint(asset, "").Canonical,
		SelectedCPE:        selectedCPE,
		ReviewStatus:       model.AssetCPEReviewStatusAccepted,
		ReviewNotes:        "CPE and NVD vulnerabilities approved by an administrator",
	}

	var updated model.Asset
	err = runAssetMatchTransaction(s.transactionRunner, ec, func(txContext *appcontext.GinContext) error {
		updated, err = s.persistMatchAnalysis(txContext, assetID, userID, analysis)
		if err != nil {
			return err
		}

		for _, cve := range cves {
			vulnerability, err := s.findOrCreateNVDVulnerability(txContext, userID, cve)
			if err != nil {
				return err
			}
			assigned, err := s.assetVulnerabilityRepository.AssignVulnerabilityForUser(txContext, updated.ID, userID, vulnerability.ID)
			if err != nil {
				if errors.Is(err, assetvulnerabilityrepo.ErrDuplicateRelationship) {
					continue
				}
				return translateMatchRepositoryError(err)
			}
			updated = assigned
		}
		if s.assetRiskService != nil {
			if err := s.assetRiskService.RefreshAssetRisk(txContext, assetID); err != nil {
				return err
			}
		}
		if s.auditService == nil {
			return nil
		}
		return s.auditService.Record(txContext, auditservice.EventInput{ActorUserID: &userID, Action: "asset_match.apply.ai_persistence", ResourceType: "asset", ResourceID: &updated.ID, Result: auditservice.ResultSucceeded, Details: "source=approved_cpe"})
	})
	if err != nil {
		return model.Asset{}, err
	}

	asset, err = s.assetMatchRepository.FindByIDForUser(ec, assetID, userID)
	return asset, translateMatchRepositoryError(err)
}

// findCVEsForAnalysis finds CVEs using the selected CPE, candidate CPEs, or keyword fallback.
func (s *assetMatchServiceImpl) findCVEsForAnalysis(ctx context.Context, analysis AssetMatchAnalysis, logger *slog.Logger) (cveMatchResult, error) {
	if strings.TrimSpace(analysis.SelectedCPE) != "" {
		logAssetMatchDebug(logger, "asset nvd cve search by selected cpe", "selected_cpe", analysis.SelectedCPE)
		cves, err := s.cveSearcher.SearchCVEsByCPE(ctx, analysis.SelectedCPE, maxAutoAttachedCVEs)
		if err != nil {
			return cveMatchResult{CVEs: cves, CPEName: analysis.SelectedCPE}, err
		}
		if len(cves) > 0 {
			return cveMatchResult{CVEs: cves, CPEName: analysis.SelectedCPE}, nil
		}
		logAssetMatchDebug(logger, "asset selected cpe returned no cves; continuing to keyword fallback",
			"selected_cpe", analysis.SelectedCPE,
		)
	}

	for _, candidate := range analysis.Candidates {
		cpeName := normalizeCPEName(candidate.CPEName)
		if cpeName == "" {
			continue
		}
		logAssetMatchDebug(logger, "asset nvd cve search by candidate cpe", "candidate_cpe", cpeName)
		cves, err := s.cveSearcher.SearchCVEsByCPE(ctx, cpeName, maxAutoAttachedCVEs)
		if err != nil {
			continue
		}
		if len(cves) > 0 {
			return cveMatchResult{CVEs: cves, CPEName: cpeName}, nil
		}
	}

	for _, cpeName := range fallbackCPENames(analysis.ProductFingerprint) {
		logAssetMatchDebug(logger, "asset nvd cve search by backend cpe fallback", "fallback_cpe", cpeName)
		cves, err := s.cveSearcher.SearchCVEsByCPE(ctx, cpeName, maxAutoAttachedCVEs)
		if err != nil {
			continue
		}
		if len(cves) > 0 {
			return cveMatchResult{CVEs: cves, CPEName: cpeName}, nil
		}
	}

	return s.findKeywordFallbackCVEs(ctx, analysis, logger)
}

// findKeywordFallbackCVEs searches and ranks keyword-based CVE candidates when CPE lookup is insufficient.
func (s *assetMatchServiceImpl) findKeywordFallbackCVEs(ctx context.Context, analysis AssetMatchAnalysis, logger *slog.Logger) (cveMatchResult, error) {
	keywordSearches := buildCVEKeywordSearches(analysis.ProductFingerprint)
	keywordSearches = s.expandCVEKeywordSearchesWithAI(ctx, analysis.ProductFingerprint, keywordSearches, logger)
	if len(keywordSearches) == 0 {
		return cveMatchResult{}, nil
	}
	logAssetMatchDebug(logger, "asset nvd cve keyword fallback planned",
		"product_fingerprint", analysis.ProductFingerprint,
		"nvd_keyword_searches", keywordSearches,
	)

	candidatesByID := make(map[string]nvdcveclient.CVELookupResponse)
	broadCandidatesByID := make(map[string]nvdcveclient.CVELookupResponse)
	usedSearches := make([]string, 0, len(keywordSearches))
	keywordFallbackUnavailable := false
	for _, keywordSearch := range keywordSearches {
		logAssetMatchDebug(logger, "asset nvd cve keyword search",
			"keyword_search", keywordSearch,
			"limit", maxKeywordFallbackNVDResults,
		)
		usedSearches = append(usedSearches, keywordSearch)
		cves, err := s.cveSearcher.SearchCVEsByKeyword(ctx, keywordSearch, maxKeywordFallbackNVDResults)
		if err != nil {
			logAssetMatchDebug(logger, "asset nvd cve keyword search failed",
				"keyword_search", keywordSearch,
				"error", err.Error(),
			)
			keywordFallbackUnavailable = true
			break
		}
		filtered := filterRelevantKeywordCVEs(cves, analysis.ProductFingerprint)
		logAssetMatchDebug(logger, "asset nvd cve keyword search returned",
			"keyword_search", keywordSearch,
			"returned_count", len(cves),
			"filtered_count", len(filtered),
			"filtered_cve_ids", cveIDs(filtered),
		)
		if len(filtered) >= maxKeywordFallbackCandidates {
			for _, cve := range filtered {
				cveID := normalizeCVEID(cve.CVEID)
				if cveID != "" {
					broadCandidatesByID[cveID] = cve
				}
			}
			continue
		}
		for _, cve := range filtered {
			cveID := normalizeCVEID(cve.CVEID)
			if cveID == "" {
				continue
			}
			candidatesByID[cveID] = cve
			if len(candidatesByID) >= maxKeywordFallbackCandidates {
				break
			}
		}
	}
	if len(candidatesByID) == 0 {
		candidatesByID = broadCandidatesByID
	}
	if len(candidatesByID) == 0 {
		if keywordFallbackUnavailable {
			return cveMatchResult{
				KeywordSearches: usedSearches,
				ReviewNotes:     "nvd cve keyword fallback unavailable",
				KeywordFallback: true,
			}, nil
		}
		return cveMatchResult{}, nil
	}

	candidates := make([]nvdcveclient.CVELookupResponse, 0, len(candidatesByID))
	for _, cve := range candidatesByID {
		candidates = append(candidates, cve)
	}
	sortCVECandidatesByPublishedAtDesc(candidates)
	logAssetMatchDebug(logger, "asset ai cve ranking input",
		"nvd_keyword_searches", usedSearches,
		"candidate_count", len(candidates),
		"candidate_cve_ids", cveIDs(candidates),
	)

	ranking, err := s.rankKeywordCVEs(ctx, analysis.ProductFingerprint, usedSearches, candidates)
	if err != nil {
		logAssetMatchDebug(logger, "asset ai cve ranking unavailable",
			"error", err.Error(),
			"candidate_count", len(candidates),
		)
		if len(candidates) == 1 {
			return cveMatchResult{
				CVEs:            candidates,
				KeywordSearches: usedSearches,
				Confidence:      minKeywordFallbackConfidence,
				ReviewNotes:     "NVD keyword fallback found one strong product match; review required",
				KeywordFallback: true,
			}, nil
		}
		return cveMatchResult{}, nil
	}
	if ranking.Confidence < minKeywordFallbackConfidence {
		logAssetMatchDebug(logger, "asset ai cve ranking rejected",
			"selected_cve_ids", ranking.SelectedCVEIDs,
			"confidence", ranking.Confidence,
			"minimum_confidence", minKeywordFallbackConfidence,
			"review_notes", ranking.ReviewNotes,
		)
		return cveMatchResult{}, nil
	}

	selected := selectRankedCVEs(candidates, ranking.SelectedCVEIDs)
	if len(selected) == 0 {
		logAssetMatchDebug(logger, "asset ai cve ranking selected no valid nvd candidates",
			"selected_cve_ids", ranking.SelectedCVEIDs,
			"candidate_cve_ids", cveIDs(candidates),
		)
		return cveMatchResult{}, nil
	}
	logAssetMatchDebug(logger, "asset ai cve ranking selected",
		"selected_cve_ids", cveIDs(selected),
		"confidence", ranking.Confidence,
		"review_notes", ranking.ReviewNotes,
	)

	return cveMatchResult{
		CVEs:            selected,
		KeywordSearches: usedSearches,
		Confidence:      ranking.Confidence,
		ReviewNotes:     firstNonEmptyString(ranking.ReviewNotes, "NVD keyword fallback returned AI-selected CVEs; review required"),
		KeywordFallback: true,
	}, nil
}

// findOrCreateNVDVulnerability creates or updates a local vulnerability from an NVD CVE response.
func (s *assetMatchServiceImpl) findOrCreateNVDVulnerability(ec *appcontext.GinContext, userID string, response nvdcveclient.CVELookupResponse) (model.Vulnerability, error) {
	normalizedCVEID := normalizeCVEID(response.CVEID)
	if err := validateCVEID(normalizedCVEID); err != nil {
		return model.Vulnerability{}, ErrInvalidCVEID
	}

	existing, err := s.vulnRepository.FindByCVEIDForUser(ec, normalizedCVEID, userID)
	if err == nil {
		updated, err := s.vulnRepository.UpdateForUser(ec, existing.ID, userID, model.Vulnerability{
			UserID:      userID,
			CVEID:       normalizedCVEID,
			Title:       firstNonEmptyString(response.Title, normalizedCVEID),
			Severity:    normalizeSeverity(response.Severity),
			Description: firstNonEmptyString(response.Description, "No description returned by NVD."),
			Status:      "Open",
		})
		return updated, translateMatchRepositoryError(err)
	}
	if !errors.Is(err, vulnerabilityrepo.ErrRecordNotFound) {
		return model.Vulnerability{}, translateMatchRepositoryError(err)
	}

	created, err := s.vulnRepository.CreateForUser(ec, userID, model.Vulnerability{
		CVEID:       normalizedCVEID,
		Title:       firstNonEmptyString(response.Title, normalizedCVEID),
		Severity:    normalizeSeverity(response.Severity),
		Description: firstNonEmptyString(response.Description, "No description returned by NVD."),
		Status:      "Open",
	})
	return created, translateMatchRepositoryError(err)
}

// persistMatchAnalysis stores match metadata on the asset assessment record.
func (s *assetMatchServiceImpl) persistMatchAnalysis(ec *appcontext.GinContext, assetID string, userID string, analysis AssetMatchAnalysis) (model.Asset, error) {
	matchedAt := s.now().UTC()
	reviewStatus := analysis.ReviewStatus
	if reviewStatus != model.AssetCPEReviewStatusAccepted {
		reviewStatus = model.AssetCPEReviewStatusNeedsReview
	}

	updated, err := s.assetMatchRepository.UpdateMatchAnalysisForUser(ec, assetID, userID, assetmatchrepo.AssetMatchUpdate{
		ProductFingerprint: stringPtrOrNil(analysis.ProductFingerprint),
		SelectedCPE:        stringPtrOrNil(analysis.SelectedCPE),
		CPEConfidence:      floatPtrOrNil(analysis.Confidence),
		CPEReviewStatus:    reviewStatus,
		CPEReviewNotes:     stringPtrOrNil(analysis.ReviewNotes),
		CPECandidateCount:  analysis.CandidateCount,
		CPEMatchedAt:       &matchedAt,
	})
	if err != nil {
		return model.Asset{}, translateMatchRepositoryError(err)
	}

	return updated, nil
}

// normalizeFingerprintWithAI asks AI to improve a weak deterministic asset fingerprint.
func (s *assetMatchServiceImpl) normalizeFingerprintWithAI(ctx context.Context, asset model.Asset, rawText string, deterministic AssetFingerprint) (AssetFingerprint, bool) {
	if s.textAI == nil {
		return AssetFingerprint{}, false
	}

	response, err := s.textAI.GenerateText(ctx, s.textGenerationBuilder().BuildAssetFingerprintExtractionRequest(
		rawText,
		deterministic.Canonical,
		asset.Name,
		asset.Type,
		optionalStringValue(asset.OperatingSystem),
	))
	if err != nil {
		return AssetFingerprint{}, false
	}

	var extraction assetFingerprintExtractionResponse
	if err := decodeRankingResponse(response.Text, &extraction); err != nil {
		fingerprint := BuildAssetFingerprint(asset, response.Text)
		if strings.TrimSpace(fingerprint.Vendor) == "" || strings.TrimSpace(fingerprint.Product) == "" {
			return AssetFingerprint{}, false
		}
		return fingerprint, true
	}
	if extractionConfidence(extraction.Confidence) < 0.45 {
		return AssetFingerprint{}, false
	}

	rawFingerprint := fingerprintExtractionRawText(extraction, deterministic)
	fingerprint := BuildAssetFingerprint(asset, rawFingerprint)
	if strings.TrimSpace(fingerprint.Vendor) == "" || strings.TrimSpace(fingerprint.Product) == "" {
		return AssetFingerprint{}, false
	}

	return fingerprint, true
}

// rankCandidates asks AI to rank bounded NVD CPE candidates for one fingerprint.
func (s *assetMatchServiceImpl) rankCandidates(ctx context.Context, fingerprint AssetFingerprint, keywordSearch string, candidates []nvdcpeclient.CPECandidate) (assetMatchRankingResponse, error) {
	request := s.textGenerationBuilder().BuildAssetMatchRankingRequest(fingerprint.Canonical, keywordSearch, candidates)
	response, err := s.textAI.GenerateText(ctx, request)
	if err != nil {
		return assetMatchRankingResponse{}, err
	}

	var ranking assetMatchRankingResponse
	if err := decodeRankingResponse(response.Text, &ranking); err != nil {
		return assetMatchRankingResponse{}, err
	}

	return ranking, nil
}

// rankKeywordCVEs asks AI to select relevant CVEs from bounded NVD keyword results.
func (s *assetMatchServiceImpl) rankKeywordCVEs(ctx context.Context, fingerprint string, keywordSearches []string, candidates []nvdcveclient.CVELookupResponse) (assetCVERankingResponse, error) {
	if s.textAI == nil {
		return assetCVERankingResponse{}, ErrMatchExternalService
	}

	request := s.textGenerationBuilder().BuildAssetCVERankingRequest(fingerprint, keywordSearches, candidates)
	response, err := s.textAI.GenerateText(ctx, request)
	if err != nil {
		return assetCVERankingResponse{}, err
	}

	var ranking assetCVERankingResponse
	if err := decodeRankingResponse(response.Text, &ranking); err != nil {
		return assetCVERankingResponse{}, err
	}

	return ranking, nil
}

// expandCVEKeywordSearchesWithAI lets AI add bounded CVE keyword searches to deterministic ones.
func (s *assetMatchServiceImpl) expandCVEKeywordSearchesWithAI(ctx context.Context, fingerprint string, deterministicSearches []string, logger *slog.Logger) []string {
	if s.textAI == nil {
		return deterministicSearches
	}

	request := s.textGenerationBuilder().BuildAssetCVEKeywordSearchRequest(fingerprint, deterministicSearches)
	response, err := s.textAI.GenerateText(ctx, request)
	if err != nil {
		logAssetMatchDebug(logger, "asset ai cve keyword search generation unavailable", "error", err.Error())
		return deterministicSearches
	}

	var generated assetCVEKeywordSearchResponse
	if err := decodeRankingResponse(response.Text, &generated); err != nil {
		logAssetMatchDebug(logger, "asset ai cve keyword search generation invalid", "error", err.Error())
		return deterministicSearches
	}

	keywordSearches := mergeCVEKeywordSearches(generated.KeywordSearches, deterministicSearches)
	logAssetMatchDebug(logger, "asset ai cve keyword search generation selected",
		"ai_keyword_searches", generated.KeywordSearches,
		"merged_keyword_searches", keywordSearches,
		"review_notes", generated.ReviewNotes,
	)

	return keywordSearches
}

// fingerprintExtractionRawText converts an AI extraction response into labeled fingerprint text.
func (s *assetMatchServiceImpl) searchCPECandidates(ctx context.Context, keywordSearches []string) (string, []nvdcpeclient.CPECandidate, error) {
	var lastErr error
	for _, keywordSearch := range keywordSearches {
		candidates, err := s.cpeSearcher.SearchCandidates(ctx, nvdcpeclient.CPEMatchRequest{KeywordSearch: keywordSearch})
		if err != nil {
			lastErr = err
			continue
		}
		if len(candidates) > 0 {
			return keywordSearch, candidates, nil
		}
	}

	if lastErr != nil {
		return keywordSearches[0], nil, lastErr
	}
	return keywordSearches[0], []nvdcpeclient.CPECandidate{}, nil
}

// buildCPEKeywordSearches creates ordered NVD CPE search terms from a fingerprint.
