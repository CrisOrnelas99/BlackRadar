// Package service provides asset-related application services.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	appcontext "blackradar/api/context"
	"blackradar/api/controller/dto"
	"blackradar/api/model"
	baserepository "blackradar/api/repository"
	assetrepo "blackradar/api/repository/asset"
	baseservice "blackradar/api/service"
	promptservice "blackradar/api/service/prompt"
)

// CPECandidateSearcher looks up NVD CPE candidates for a normalized search request.
type CPECandidateSearcher interface {
	SearchCandidates(ctx context.Context, request dto.CPEMatchRequest) ([]dto.CPECandidate, error)
}

// CVEByCPESearcher looks up NVD CVEs for selected CPEs and bounded keyword fallback searches.
type CVEByCPESearcher interface {
	SearchCVEsByCPE(ctx context.Context, cpeName string, limit int) ([]dto.CVELookupResponse, error)
	SearchCVEsByKeyword(ctx context.Context, keywordSearch string, limit int) ([]dto.CVELookupResponse, error)
}

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
	Candidates         []dto.CPECandidate
}

type assetMatchServiceImpl struct {
	assetRepository baserepository.AssetRepository
	vulnRepository  baserepository.VulnerabilityRepository
	cpeSearcher     CPECandidateSearcher
	cveSearcher     CVEByCPESearcher
	textAI          baseservice.TextGenerationService
	now             func() time.Time
}

// NewAssetMatchService creates a backend-only asset matching service.
func NewAssetMatchService(assetRepository baserepository.AssetRepository, vulnRepository baserepository.VulnerabilityRepository, cpeSearcher CPECandidateSearcher, cveSearcher CVEByCPESearcher, textAI baseservice.TextGenerationService) *assetMatchServiceImpl {
	return &assetMatchServiceImpl{
		assetRepository: assetRepository,
		vulnRepository:  vulnRepository,
		cpeSearcher:     cpeSearcher,
		cveSearcher:     cveSearcher,
		textAI:          textAI,
		now:             time.Now,
	}
}

// AnalyzeAssetMatch builds a fingerprint, fetches NVD candidates, and asks the AI layer to rank them.
func (s *assetMatchServiceImpl) AnalyzeAssetMatch(ctx context.Context, asset model.Asset, rawText string) (AssetMatchAnalysis, error) {
	sanitizedText := ""
	if strings.TrimSpace(rawText) != "" {
		var err error
		sanitizedText, err = baseservice.SanitizeAIIngestionText(rawText)
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

// AnalyzeAndPersistAssetMatch analyzes an asset and stores the result on the asset record.
func (s *assetMatchServiceImpl) AnalyzeAndPersistAssetMatch(ec *appcontext.GinContext, assetID string) (model.Asset, error) {
	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	asset, err := s.assetRepository.FindByIDForOrganization(ec, assetID, organizationID)
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	analysis, err := s.AnalyzeAssetMatch(ec.RequestContext(), asset, "")
	if err != nil {
		return model.Asset{}, err
	}

	matchedAt := s.now().UTC()
	reviewStatus := analysis.ReviewStatus
	if reviewStatus != model.AssetCPEReviewStatusAccepted {
		reviewStatus = model.AssetCPEReviewStatusNeedsReview
	}

	updated, err := s.assetRepository.UpdateMatchAnalysisForOrganization(ec, assetID, organizationID, assetrepo.AssetMatchUpdate{
		ProductFingerprint: stringPtrOrNil(analysis.ProductFingerprint),
		SelectedCPE:        stringPtrOrNil(analysis.SelectedCPE),
		CPEConfidence:      floatPtrOrNil(analysis.Confidence),
		CPEReviewStatus:    reviewStatus,
		CPEReviewNotes:     stringPtrOrNil(analysis.ReviewNotes),
		CPECandidateCount:  analysis.CandidateCount,
		CPEMatchedAt:       &matchedAt,
	})
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	return updated, nil
}

// AnalyzePersistAndAttachVulnerabilities matches a CPE, fetches NVD CVEs for it, and attaches them to the asset.
func (s *assetMatchServiceImpl) AnalyzePersistAndAttachVulnerabilities(ec *appcontext.GinContext, assetID string) (model.Asset, error) {
	role, err := baseservice.AuthenticatedRole(ec)
	if err != nil {
		return model.Asset{}, baseservice.ErrForbidden
	}
	if !baseservice.CanManageVulnerabilities(role) {
		return model.Asset{}, baseservice.ErrForbidden
	}
	if s.vulnRepository == nil || s.cveSearcher == nil {
		return model.Asset{}, baseservice.ErrExternalService
	}

	organizationID, err := baseservice.AuthenticatedOrganizationID(ec)
	if err != nil {
		return model.Asset{}, err
	}

	asset, err := s.assetRepository.FindByIDForOrganization(ec, assetID, organizationID)
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	analysis, err := s.AnalyzeAssetMatch(ec.RequestContext(), asset, "")
	if err != nil {
		return model.Asset{}, err
	}
	ec.Logger().Info("asset cpe match analysis",
		"asset_id", assetID,
		"product_fingerprint", analysis.ProductFingerprint,
		"nvd_cpe_keyword_search", analysis.KeywordSearch,
		"nvd_cpe_candidate_count", analysis.CandidateCount,
		"selected_cpe", analysis.SelectedCPE,
		"review_status", analysis.ReviewStatus,
	)

	matchResult, err := s.findCVEsForAnalysis(ec.RequestContext(), analysis, ec.Logger())
	if err != nil {
		analysis.ReviewStatus = model.AssetCPEReviewStatusNeedsReview
		analysis.ReviewNotes = "nvd cve search failed"
		return s.persistMatchAnalysis(ec, assetID, organizationID, analysis)
	}
	if len(matchResult.CVEs) == 0 {
		analysis.ReviewStatus = model.AssetCPEReviewStatusNeedsReview
		analysis.ReviewNotes = firstNonEmptyString(matchResult.ReviewNotes, analysis.ReviewNotes, "no NVD CVEs returned for selected CPE")
		return s.persistMatchAnalysis(ec, assetID, organizationID, analysis)
	}
	if matchResult.KeywordFallback {
		ec.Logger().Info("asset cve keyword fallback selected",
			"asset_id", assetID,
			"nvd_keyword_searches", matchResult.KeywordSearches,
			"selected_cve_ids", cveIDs(matchResult.CVEs),
			"ai_confidence", matchResult.Confidence,
			"ai_review_notes", matchResult.ReviewNotes,
		)
		analysis.SelectedCPE = ""
		analysis.Confidence = matchResult.Confidence
		analysis.ReviewStatus = model.AssetCPEReviewStatusNeedsReview
		analysis.ReviewNotes = firstNonEmptyString(matchResult.ReviewNotes, "NVD keyword fallback returned AI-selected CVEs; review required")
	} else if strings.TrimSpace(analysis.SelectedCPE) == "" {
		analysis.SelectedCPE = matchResult.CPEName
		analysis.Confidence = 0.8
		analysis.ReviewStatus = model.AssetCPEReviewStatusNeedsReview
		analysis.ReviewNotes = "NVD returned CVEs for a backend-built CPE candidate; review recommended"
	}

	updated, err := s.persistMatchAnalysis(ec, assetID, organizationID, analysis)
	if err != nil {
		return model.Asset{}, err
	}

	for _, cve := range matchResult.CVEs {
		vulnerability, err := s.findOrSaveNVDVulnerability(ec, organizationID, cve)
		if err != nil {
			return model.Asset{}, err
		}
		assigned, err := s.assetRepository.AssignVulnerabilityForOrganization(ec, updated.ID, organizationID, vulnerability.ID)
		if err != nil {
			if errors.Is(err, baserepository.ErrDuplicateAssignment) {
				continue
			}
			return model.Asset{}, baseservice.TranslateRepositoryError(err)
		}
		updated = assigned
	}

	return s.assetRepository.FindByIDForOrganization(ec, assetID, organizationID)
}

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
		if cpeName == "" || !candidateVersionMatchesFingerprint(cpeName, analysis.ProductFingerprint) {
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

	candidatesByID := make(map[string]dto.CVELookupResponse)
	broadCandidatesByID := make(map[string]dto.CVELookupResponse)
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
				cveID := baseservice.NormalizeCVEID(cve.CVEID)
				if cveID != "" {
					broadCandidatesByID[cveID] = cve
				}
			}
			continue
		}
		for _, cve := range filtered {
			cveID := baseservice.NormalizeCVEID(cve.CVEID)
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

	candidates := make([]dto.CVELookupResponse, 0, len(candidatesByID))
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

func (s *assetMatchServiceImpl) findOrSaveNVDVulnerability(ec *appcontext.GinContext, organizationID string, response dto.CVELookupResponse) (model.Vulnerability, error) {
	userID, err := baseservice.AuthenticatedUserID(ec)
	if err != nil {
		return model.Vulnerability{}, err
	}

	normalizedCVEID := baseservice.NormalizeCVEID(response.CVEID)
	if err := baseservice.ValidateCVEID(normalizedCVEID); err != nil {
		return model.Vulnerability{}, err
	}

	existing, err := s.vulnRepository.FindByCVEIDForOrganization(ec, normalizedCVEID, organizationID)
	if err == nil {
		return s.vulnRepository.UpdateForOrganization(ec, existing.ID, organizationID, model.Vulnerability{
			OrganizationID: organizationID,
			UserID:         userID,
			CVEID:          normalizedCVEID,
			Title:          firstNonEmptyString(response.Title, normalizedCVEID),
			Severity:       baseservice.NormalizeSeverity(response.Severity),
			Description:    firstNonEmptyString(response.Description, "No description returned by NVD."),
			Status:         "Open",
		})
	}
	if !errors.Is(err, baserepository.ErrVulnerabilityNotFound) {
		return model.Vulnerability{}, baseservice.TranslateRepositoryError(err)
	}

	return s.vulnRepository.Save(ec, model.Vulnerability{
		OrganizationID: organizationID,
		UserID:         userID,
		CVEID:          normalizedCVEID,
		Title:          firstNonEmptyString(response.Title, normalizedCVEID),
		Severity:       baseservice.NormalizeSeverity(response.Severity),
		Description:    firstNonEmptyString(response.Description, "No description returned by NVD."),
		Status:         "Open",
	})
}

func (s *assetMatchServiceImpl) persistMatchAnalysis(ec *appcontext.GinContext, assetID string, organizationID string, analysis AssetMatchAnalysis) (model.Asset, error) {
	matchedAt := s.now().UTC()
	reviewStatus := analysis.ReviewStatus
	if reviewStatus != model.AssetCPEReviewStatusAccepted {
		reviewStatus = model.AssetCPEReviewStatusNeedsReview
	}

	updated, err := s.assetRepository.UpdateMatchAnalysisForOrganization(ec, assetID, organizationID, assetrepo.AssetMatchUpdate{
		ProductFingerprint: stringPtrOrNil(analysis.ProductFingerprint),
		SelectedCPE:        stringPtrOrNil(analysis.SelectedCPE),
		CPEConfidence:      floatPtrOrNil(analysis.Confidence),
		CPEReviewStatus:    reviewStatus,
		CPEReviewNotes:     stringPtrOrNil(analysis.ReviewNotes),
		CPECandidateCount:  analysis.CandidateCount,
		CPEMatchedAt:       &matchedAt,
	})
	if err != nil {
		return model.Asset{}, baseservice.TranslateRepositoryError(err)
	}

	return updated, nil
}

type assetMatchRankingResponse struct {
	SelectedCPE string   `json:"selectedCpe"`
	Confidence  float64  `json:"confidence"`
	ReviewNotes string   `json:"reviewNotes"`
	RankedCPEs  []string `json:"rankedCpes"`
}

type assetCVERankingResponse struct {
	SelectedCVEIDs []string `json:"selectedCveIds"`
	Confidence     float64  `json:"confidence"`
	ReviewNotes    string   `json:"reviewNotes"`
}

type assetCVEKeywordSearchResponse struct {
	KeywordSearches []string `json:"keywordSearches"`
	ReviewNotes     string   `json:"reviewNotes"`
}

type cveMatchResult struct {
	CVEs            []dto.CVELookupResponse
	CPEName         string
	KeywordSearches []string
	Confidence      float64
	ReviewNotes     string
	KeywordFallback bool
}

type assetFingerprintExtractionResponse struct {
	Vendor          any `json:"vendor"`
	Product         any `json:"product"`
	Version         any `json:"version"`
	OperatingSystem any `json:"operatingSystem"`
	DeviceModel     any `json:"deviceModel"`
	Confidence      any `json:"confidence"`
	ReviewNotes     any `json:"reviewNotes"`
}

func (s *assetMatchServiceImpl) normalizeFingerprintWithAI(ctx context.Context, asset model.Asset, rawText string, deterministic AssetFingerprint) (AssetFingerprint, bool) {
	if s.textAI == nil {
		return AssetFingerprint{}, false
	}

	response, err := s.textAI.GenerateText(ctx, promptservice.BuildAssetFingerprintExtractionRequest(
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

func (s *assetMatchServiceImpl) rankCandidates(ctx context.Context, fingerprint AssetFingerprint, keywordSearch string, candidates []dto.CPECandidate) (assetMatchRankingResponse, error) {
	request := promptservice.BuildAssetMatchRankingRequest(fingerprint.Canonical, keywordSearch, candidates)
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

func (s *assetMatchServiceImpl) rankKeywordCVEs(ctx context.Context, fingerprint string, keywordSearches []string, candidates []dto.CVELookupResponse) (assetCVERankingResponse, error) {
	if s.textAI == nil {
		return assetCVERankingResponse{}, baseservice.ErrExternalService
	}

	request := promptservice.BuildAssetCVERankingRequest(fingerprint, keywordSearches, candidates)
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

func (s *assetMatchServiceImpl) expandCVEKeywordSearchesWithAI(ctx context.Context, fingerprint string, deterministicSearches []string, logger *slog.Logger) []string {
	if s.textAI == nil {
		return deterministicSearches
	}

	request := promptservice.BuildAssetCVEKeywordSearchRequest(fingerprint, deterministicSearches)
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

func fingerprintExtractionRawText(extraction assetFingerprintExtractionResponse, fallback AssetFingerprint) string {
	values := []string{
		"Vendor: " + firstNonEmptyString(jsonStringValue(extraction.Vendor), fallback.Vendor),
		"Product: " + firstNonEmptyString(jsonStringValue(extraction.Product), fallback.Product),
		"Version: " + firstNonEmptyString(jsonStringValue(extraction.Version), fallback.Version),
		"Operating System: " + firstNonEmptyString(jsonStringValue(extraction.OperatingSystem), fallback.OperatingSystem),
		"Model: " + firstNonEmptyString(jsonStringValue(extraction.DeviceModel), fallback.DeviceModel),
	}

	lines := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(strings.TrimSuffix(value, ": ")) != "" && !strings.HasSuffix(value, ": ") {
			lines = append(lines, value)
		}
	}
	return strings.Join(lines, "\n")
}

func jsonStringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func extractionConfidence(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "high", "strong":
			return 0.9
		case "medium", "moderate":
			return 0.65
		case "low", "weak":
			return 0.3
		default:
			return 0
		}
	default:
		return 0
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func optionalStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func fallbackCPENames(canonicalFingerprint string) []string {
	fields := parseCanonicalFingerprint(canonicalFingerprint)
	vendor := fields["vendor"]
	product := fields["product"]
	version := fields["version"]
	if vendor == "" || product == "" || version == "" {
		return nil
	}

	candidates := make([]string, 0, 24)
	for _, vendorAlias := range cpeComponentAliases(vendor) {
		for _, productAlias := range cpeProductAliases(product, fields["operating_system"]) {
			for _, part := range []string{"a", "o", "h"} {
				cpeName := "cpe:2.3:" + part + ":" + vendorAlias + ":" + productAlias + ":" + cpeComponent(version) + ":*:*:*:*:*:*:*"
				if !containsString(candidates, cpeName) {
					candidates = append(candidates, cpeName)
				}
			}
		}
	}

	return candidates
}

func parseCanonicalFingerprint(canonicalFingerprint string) map[string]string {
	fields := make(map[string]string)
	for _, part := range strings.Split(canonicalFingerprint, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return fields
}

func cpeComponentAliases(value string) []string {
	normalized := cpeComponent(value)
	aliases := []string{normalized}
	for _, suffix := range []string{"_software_foundation", "_software", "_utils", "_project"} {
		if strings.HasSuffix(normalized, suffix) {
			alias := strings.TrimSuffix(normalized, suffix)
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
	}
	if normalized == "xz_utils" && !containsString(aliases, "xz") {
		aliases = append(aliases, "xz")
	}
	return aliases
}

func cpeComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(" ", "_", "-", "_").Replace(value)
	return strings.Trim(value, "_")
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s *assetMatchServiceImpl) searchCPECandidates(ctx context.Context, keywordSearches []string) (string, []dto.CPECandidate, error) {
	var lastErr error
	for _, keywordSearch := range keywordSearches {
		candidates, err := s.cpeSearcher.SearchCandidates(ctx, dto.CPEMatchRequest{KeywordSearch: keywordSearch})
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
	return keywordSearches[0], []dto.CPECandidate{}, nil
}

func buildCPEKeywordSearches(fingerprint AssetFingerprint) []string {
	searches := make([]string, 0, 5)
	appendSearch := func(parts ...string) {
		values := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				values = append(values, part)
			}
		}
		search := strings.Join(values, " ")
		if search == "" {
			return
		}
		for _, existing := range searches {
			if existing == search {
				return
			}
		}
		searches = append(searches, search)
	}

	for _, vendor := range keywordAliases(fingerprint.Vendor) {
		for _, product := range keywordProductAliases(fingerprint.Product, fingerprint.OperatingSystem) {
			appendSearch(vendor, product)
			appendSearch(vendor, product, fingerprint.Version)
			appendSearch(product, fingerprint.Version)
			appendSearch(vendor, product, fingerprint.OperatingSystem)
			appendSearch(product)
		}
	}

	return searches
}

func buildCVEKeywordSearches(canonicalFingerprint string) []string {
	fields := parseCanonicalFingerprint(canonicalFingerprint)
	product := fields["product"]
	version := fields["version"]
	assetName := fields["asset_name"]
	deviceModel := fields["device_model"]
	operatingSystem := fields["operating_system"]
	nameFallback := strings.TrimSpace(product) == ""

	searches := make([]string, 0, maxKeywordFallbackSearches)
	appendSearch := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || containsString(searches, value) || len(searches) >= maxKeywordFallbackSearches {
			return
		}
		searches = append(searches, value)
	}

	appendSearch(trimGenericProductSuffixPreservingSeparators(product))
	normalizedProduct := normalizedSearchPhrase(product)
	withoutGenericSuffix := trimGenericProductSuffix(normalizedProduct)
	if withoutGenericSuffix != "" {
		appendSearch(withoutGenericSuffix)
	}
	appendSearch(normalizedProduct)
	for _, variant := range productContextKeywordVariants(normalizedProduct, assetName, deviceModel, operatingSystem, fields["asset_type"]) {
		appendSearch(variant)
	}
	appendNGrams := func(value string, size int) {
		for _, phrase := range nGramSearches(value, size) {
			appendSearch(phrase)
		}
	}
	appendNGrams(product, 3)
	if nameFallback {
		appendNGrams(assetName, 3)
	}
	if version != "" && withoutGenericSuffix != "" {
		appendSearch(withoutGenericSuffix + " " + version)
	}
	if strings.Contains(normalizedSearchPhrase(product+" "+assetName+" "+deviceModel+" "+operatingSystem), "wordpress") ||
		strings.Contains(normalizedSearchPhrase(product+" "+assetName+" "+deviceModel), "plugin") {
		appendSearch("wordpress plugin")
	}
	appendNGrams(product, 2)
	if nameFallback {
		appendNGrams(assetName, 2)
	}

	return searches
}

func mergeCVEKeywordSearches(primary []string, fallback []string) []string {
	searches := make([]string, 0, maxKeywordFallbackSearches)
	appendSearch := func(value string) {
		value = normalizeAIKeywordSearch(value)
		if value == "" || containsString(searches, value) || len(searches) >= maxKeywordFallbackSearches {
			return
		}
		searches = append(searches, value)
	}

	for index, value := range fallback {
		if index >= 3 {
			break
		}
		appendSearch(value)
	}
	for _, value := range primary {
		appendSearch(value)
	}
	for _, value := range fallback {
		appendSearch(value)
	}

	return searches
}

func productContextKeywordVariants(product string, assetName string, deviceModel string, operatingSystem string, assetType string) []string {
	product = normalizedSearchPhrase(product)
	if product == "" {
		return nil
	}

	context := normalizedSearchPhrase(product + " " + assetName + " " + deviceModel + " " + operatingSystem + " " + assetType)
	variants := make([]string, 0, 4)
	appendVariant := func(suffix string) {
		variant := strings.TrimSpace(product + " " + suffix)
		if variant != "" && !containsString(variants, variant) {
			variants = append(variants, variant)
		}
	}

	if strings.Contains(context, "network") || strings.Contains(context, "controller") {
		appendVariant("application")
		appendVariant("controller")
	}
	if strings.Contains(context, "device") || strings.Contains(context, "firmware") {
		appendVariant("firmware")
	}
	if strings.Contains(context, "plugin") {
		appendVariant("plugin")
	}
	if strings.Contains(context, "library") || strings.Contains(context, "wrapper") {
		appendVariant("library")
		appendVariant("wrapper")
	}

	return variants
}

func normalizeAIKeywordSearch(value string) string {
	value = normalizedSearchPhrase(value)
	if value == "" || len(value) > 120 {
		return ""
	}

	words := strings.Fields(value)
	if len(words) < 2 || len(words) > 6 {
		return ""
	}
	for _, word := range words {
		if len(word) > 40 {
			return ""
		}
	}

	for _, broad := range []string{"aws", "windows", "linux", "wordpress", "network device"} {
		if value == broad {
			return ""
		}
	}

	return value
}

func keywordAliases(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return []string{""}
	}

	aliases := []string{value}
	for _, suffix := range []string{" software foundation", " software", " utils", " project"} {
		if strings.HasSuffix(value, suffix) {
			alias := strings.TrimSpace(strings.TrimSuffix(value, suffix))
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
	}
	if value == "xz utils" && !containsString(aliases, "xz") {
		aliases = append(aliases, "xz")
	}
	return aliases
}

func filterRelevantKeywordCVEs(cves []dto.CVELookupResponse, canonicalFingerprint string) []dto.CVELookupResponse {
	aliases := productRelevanceAliases(canonicalFingerprint)
	if len(aliases) == 0 {
		return nil
	}

	filtered := make([]dto.CVELookupResponse, 0, len(cves))
	for _, cve := range cves {
		text := normalizedSearchPhrase(cve.Title + " " + cve.Description)
		for _, alias := range aliases {
			if alias != "" && strings.Contains(text, alias) {
				filtered = append(filtered, cve)
				break
			}
		}
	}
	return filtered
}

func productRelevanceAliases(canonicalFingerprint string) []string {
	fields := parseCanonicalFingerprint(canonicalFingerprint)
	values := []string{fields["product"]}
	if strings.TrimSpace(fields["product"]) == "" {
		values = append(values, fields["asset_name"])
	}
	values = append(values, fields["device_model"])

	aliases := make([]string, 0, 8)
	appendAlias := func(value string) {
		value = normalizedSearchPhrase(value)
		if value == "" || containsString(aliases, value) {
			return
		}
		if len(strings.Fields(value)) < 2 {
			return
		}
		aliases = append(aliases, value)
	}

	for _, value := range values {
		appendAlias(value)
		appendAlias(trimGenericProductSuffix(value))
		for _, phrase := range nGramSearches(value, 3) {
			appendAlias(phrase)
		}
	}
	return aliases
}

func selectRankedCVEs(candidates []dto.CVELookupResponse, selectedCVEIDs []string) []dto.CVELookupResponse {
	byID := make(map[string]dto.CVELookupResponse, len(candidates))
	for _, cve := range candidates {
		cveID := baseservice.NormalizeCVEID(cve.CVEID)
		if cveID != "" {
			byID[cveID] = cve
		}
	}

	selected := make([]dto.CVELookupResponse, 0, min(len(selectedCVEIDs), maxAutoAttachedCVEs))
	for _, cveID := range selectedCVEIDs {
		cve, ok := byID[baseservice.NormalizeCVEID(cveID)]
		if !ok {
			continue
		}
		if containsCVEID(selected, cve.CVEID) {
			continue
		}
		selected = append(selected, cve)
		if len(selected) >= maxAutoAttachedCVEs {
			break
		}
	}
	return selected
}

func sortCVECandidatesByPublishedAtDesc(candidates []dto.CVELookupResponse) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left := strings.TrimSpace(candidates[i].PublishedAt)
		right := strings.TrimSpace(candidates[j].PublishedAt)
		if left == "" {
			return false
		}
		if right == "" {
			return true
		}
		return left > right
	})
}

func containsCVEID(cves []dto.CVELookupResponse, cveID string) bool {
	cveID = baseservice.NormalizeCVEID(cveID)
	for _, cve := range cves {
		if baseservice.NormalizeCVEID(cve.CVEID) == cveID {
			return true
		}
	}
	return false
}

func cveIDs(cves []dto.CVELookupResponse) []string {
	ids := make([]string, 0, len(cves))
	for _, cve := range cves {
		cveID := baseservice.NormalizeCVEID(cve.CVEID)
		if cveID != "" && !containsString(ids, cveID) {
			ids = append(ids, cveID)
		}
	}
	return ids
}

func logAssetMatchDebug(logger *slog.Logger, message string, args ...any) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info(message, args...)
}

func nGramSearches(value string, size int) []string {
	words := strings.Fields(normalizedSearchPhrase(value))
	if size <= 0 || len(words) < size {
		return nil
	}

	searches := make([]string, 0, len(words)-size+1)
	for index := 0; index <= len(words)-size; index++ {
		searches = append(searches, strings.Join(words[index:index+size], " "))
	}
	return searches
}

func trimGenericProductSuffix(value string) string {
	words := strings.Fields(normalizedSearchPhrase(value))
	for len(words) > 2 {
		last := words[len(words)-1]
		switch last {
		case "plugin", "plugins", "software", "firmware", "application", "app", "controller":
			words = words[:len(words)-1]
		default:
			return strings.Join(words, " ")
		}
	}
	return strings.Join(words, " ")
}

func trimGenericProductSuffixPreservingSeparators(value string) string {
	value = strings.TrimSpace(value)
	for _, suffix := range []string{" plugin", " plugins", " software", " firmware", " application", " app"} {
		if strings.HasSuffix(strings.ToLower(value), suffix) && len(strings.Fields(normalizedSearchPhrase(value))) > 2 {
			return strings.TrimSpace(value[:len(value)-len(suffix)])
		}
	}
	return value
}

func normalizedSearchPhrase(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return ' '
		}
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

func keywordProductAliases(product string, operatingSystem string) []string {
	aliases := keywordAliases(product)
	if shouldTryFirmwareAlias(product, operatingSystem) {
		firmwareProduct := strings.TrimSpace(product + " firmware")
		if firmwareProduct != "" && !containsString(aliases, firmwareProduct) {
			aliases = append(aliases, firmwareProduct)
		}
		normalizedOS := strings.TrimSpace(operatingSystem)
		if normalizedOS != "" && !containsString(aliases, normalizedOS) {
			aliases = append(aliases, normalizedOS)
		}
	}
	return aliases
}

func cpeProductAliases(product string, operatingSystem string) []string {
	aliases := cpeComponentAliases(product)
	if shouldTryFirmwareAlias(product, operatingSystem) {
		for _, alias := range cpeComponentAliases(product + " firmware") {
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
		for _, alias := range cpeComponentAliases(operatingSystem) {
			if alias != "" && !containsString(aliases, alias) {
				aliases = append(aliases, alias)
			}
		}
	}
	return aliases
}

func shouldTryFirmwareAlias(product string, operatingSystem string) bool {
	product = strings.ToLower(strings.TrimSpace(product))
	operatingSystem = strings.ToLower(strings.TrimSpace(operatingSystem))
	return product != "" && strings.Contains(operatingSystem, "firmware") && !strings.Contains(product, "firmware")
}

func isStrongFingerprint(fingerprint AssetFingerprint) bool {
	return strings.TrimSpace(fingerprint.Vendor) != "" && strings.TrimSpace(fingerprint.Product) != ""
}

func containsCPECandidate(candidates []dto.CPECandidate, cpeName string) bool {
	for _, candidate := range candidates {
		if normalizeCPEName(candidate.CPEName) == normalizeCPEName(cpeName) {
			return true
		}
	}
	return false
}

func normalizeCPEName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func selectedCPEVersionMatches(cpeName string, fingerprintVersion string) bool {
	return true
}

func candidateVersionMatchesFingerprint(cpeName string, canonicalFingerprint string) bool {
	return true
}

func decodeRankingResponse(raw string, target any) error {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return fmt.Errorf("%w: empty response", baseservice.ErrExternalService)
	}
	if err := json.Unmarshal([]byte(trimmed), target); err != nil {
		return fmt.Errorf("%w: decode ranking response", baseservice.ErrExternalService)
	}
	return nil
}

func stringPtrOrNil(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	trimmed := strings.TrimSpace(value)
	return &trimmed
}

func floatPtrOrNil(value float64) *float64 {
	if value <= 0 {
		return nil
	}
	copied := value
	return &copied
}
