// Package repository support contains shared helpers for asset persistence.
package repository

import (
	"errors"
	"fmt"
	"strings"

	commonid "blackradar/api/common/id"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"

	"gorm.io/gorm"
)

const vulnerabilityCountColumn = "COALESCE(asset_vulnerability_counts.vulnerability_count, 0)"

func assetSummaryDatabase(database *gorm.DB, userID string) *gorm.DB {
	return database.Table("assets").
		Select(`
			COUNT(*) AS total_count,
			COALESCE(SUM(CASE WHEN COALESCE(asset_assessments.selected_cpe, '') = '' THEN 1 ELSE 0 END), 0) AS unscanned_count,
			COALESCE(SUM(CASE WHEN EXISTS (
				SELECT 1
				FROM asset_vulnerabilities av
				JOIN vulnerabilities v ON v.id = av.vulnerability_id AND v.organization_id = assets.organization_id AND v.deleted_at IS NULL
				WHERE av.asset_id = assets.id AND av.deleted_at IS NULL
			) THEN 1 ELSE 0 END), 0) AS with_vulnerabilities_count,
			COALESCE(SUM(CASE WHEN LOWER(COALESCE(assets.risk_level, 'Low')) = 'low' THEN 1 ELSE 0 END), 0) AS low_risk_count,
			COALESCE(SUM(CASE WHEN LOWER(COALESCE(assets.risk_level, 'Low')) = 'medium' THEN 1 ELSE 0 END), 0) AS medium_risk_count,
			COALESCE(SUM(CASE WHEN LOWER(COALESCE(assets.risk_level, 'Low')) = 'high' THEN 1 ELSE 0 END), 0) AS high_risk_count,
			COALESCE(SUM(CASE WHEN LOWER(COALESCE(assets.risk_level, 'Low')) = 'critical' THEN 1 ELSE 0 END), 0) AS critical_risk_count`).
		Joins("LEFT JOIN asset_assessments ON asset_assessments.id = assets.asset_assessment_id AND asset_assessments.deleted_at IS NULL").
		Where("assets.organization_id = (SELECT organization_id FROM users WHERE id = ?) AND assets.deleted_at IS NULL", userID)
}

func assetListDatabase(database *gorm.DB, userID string) *gorm.DB {
	vulnerabilityCounts := database.Session(&gorm.Session{NewDB: true}).
		Table("asset_vulnerabilities av").
		Select("av.asset_id, COUNT(*) AS vulnerability_count").
		Joins("JOIN vulnerabilities v ON v.id = av.vulnerability_id AND v.organization_id = (SELECT organization_id FROM users WHERE id = ?) AND v.deleted_at IS NULL", userID).
		Where("av.deleted_at IS NULL").
		Group("av.asset_id")

	return database.Model(&model.Asset{}).
		Joins("LEFT JOIN (?) asset_vulnerability_counts ON asset_vulnerability_counts.asset_id = assets.id", vulnerabilityCounts).
		Where("assets.organization_id = (SELECT organization_id FROM users WHERE id = ?)", userID)
}

func applyAssetListFilters(database *gorm.DB, query model.AssetListQuery) *gorm.DB {
	if query.Search != "" {
		database = database.Where(`LOWER(assets.name) LIKE ? ESCAPE '\'`, assetSearchPattern(query.Search))
	}
	filters := []struct {
		column string
		value  string
	}{
		{column: "assets.criticality", value: query.Criticality},
		{column: "COALESCE(assets.risk_level, 'Low')", value: query.RiskLevel},
		{column: "assets.type", value: query.Type},
		{column: "assets.owner", value: query.Owner},
		{column: "COALESCE(assets.operating_system, '')", value: query.OperatingSystem},
		{column: "COALESCE(assets.vendor, '')", value: query.Vendor},
		{column: "COALESCE(assets.product, '')", value: query.Product},
		{column: "COALESCE(assets.version, '')", value: query.Version},
	}
	for _, filter := range filters {
		if filter.value != "" {
			database = database.Where("LOWER("+filter.column+") = LOWER(?)", filter.value)
		}
	}

	if query.VulnerabilityValue == nil || query.VulnerabilityMode == model.AssetVulnerabilityFilterAny {
		return database
	}
	operator := "="
	switch query.VulnerabilityMode {
	case model.AssetVulnerabilityFilterAtLeast:
		operator = ">="
	case model.AssetVulnerabilityFilterAtMost:
		operator = "<="
	}
	return database.Where(vulnerabilityCountColumn+" "+operator+" ?", *query.VulnerabilityValue)
}

func assetSearchPattern(value string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(value))
	return "%" + escaped + "%"
}

func assetListOrder(query model.AssetListQuery) string {
	column := "LOWER(assets.name)"
	switch query.SortField {
	case model.AssetSortCriticality:
		column = "LOWER(assets.criticality)"
	case model.AssetSortRiskLevel:
		column = "LOWER(COALESCE(assets.risk_level, 'Low'))"
	case model.AssetSortVulnerabilityCount:
		column = vulnerabilityCountColumn
	case model.AssetSortType:
		column = "LOWER(assets.type)"
	case model.AssetSortOwner:
		column = "LOWER(assets.owner)"
	case model.AssetSortOperatingSystem:
		column = "LOWER(COALESCE(assets.operating_system, ''))"
	case model.AssetSortVendor:
		column = "LOWER(COALESCE(assets.vendor, ''))"
	case model.AssetSortProduct:
		column = "LOWER(COALESCE(assets.product, ''))"
	case model.AssetSortVersion:
		column = "LOWER(COALESCE(assets.version, ''))"
	}
	direction := "ASC"
	if query.SortDirection == model.AssetSortDescending {
		direction = "DESC"
	}
	return column + " " + direction
}

// dbForContext returns the request-scoped database when present, otherwise the repository database.
func (r *AssetRepository) dbForContext(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

// loadActiveVulnerabilitiesForAsset loads active vulnerability assignments for an asset.
func (r *AssetRepository) loadActiveVulnerabilitiesForAsset(ec *appcontext.GinContext, asset *model.Asset, userID string) error {
	vulnerabilities, err := r.FindVulnerabilitiesForAsset(ec, asset.ID, userID)
	if err != nil {
		return err
	}
	asset.Vulnerabilities = vulnerabilities
	return nil
}

// FindVulnerabilitiesForAsset returns active vulnerabilities attached to an owned asset.
func (r *AssetRepository) FindVulnerabilitiesForAsset(ec *appcontext.GinContext, assetID string, userID string) ([]model.Vulnerability, error) {
	var vulnerabilities []model.Vulnerability
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.Vulnerability{}).
		Joins("JOIN asset_vulnerabilities av ON av.vulnerability_id = vulnerabilities.id AND av.deleted_at IS NULL").
		Where("av.asset_id = ? AND vulnerabilities.organization_id = (SELECT organization_id FROM users WHERE id = ?) AND vulnerabilities.deleted_at IS NULL", assetID, userID).
		Order("vulnerabilities.id").
		Find(&vulnerabilities).Error
	if err != nil {
		return nil, fmt.Errorf("%w: load asset vulnerabilities: %w", ErrPersistenceFailure, err)
	}
	if err := r.loadAffectedAssetCounts(ec, vulnerabilities, userID); err != nil {
		return nil, err
	}
	return vulnerabilities, nil
}

// loadAffectedAssetCounts adds active owned-asset counts to vulnerabilities.
func (r *AssetRepository) loadAffectedAssetCounts(ec *appcontext.GinContext, vulnerabilities []model.Vulnerability, userID string) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	type affectedAssetCount struct {
		VulnerabilityID string
		Count           int64
	}

	vulnerabilityIDs := make([]string, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		vulnerabilityIDs = append(vulnerabilityIDs, vulnerability.ID)
	}

	var counts []affectedAssetCount
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Table("asset_vulnerabilities av").
		Select("av.vulnerability_id, COUNT(*) AS count").
		Joins("JOIN assets a ON a.id = av.asset_id AND a.organization_id = (SELECT organization_id FROM users WHERE id = ?) AND a.deleted_at IS NULL", userID).
		Where("av.vulnerability_id IN ? AND av.deleted_at IS NULL", vulnerabilityIDs).
		Group("av.vulnerability_id").
		Scan(&counts).Error
	if err != nil {
		return fmt.Errorf("%w: count vulnerability assets: %w", ErrPersistenceFailure, err)
	}

	countByVulnerabilityID := make(map[string]int, len(counts))
	for _, count := range counts {
		countByVulnerabilityID[count.VulnerabilityID] = int(count.Count)
	}
	for index := range vulnerabilities {
		vulnerabilities[index].AffectedAssetCount = countByVulnerabilityID[vulnerabilities[index].ID]
	}

	return nil
}

// createAssetAssessmentWithRandomID persists an asset assessment with a random public identifier.
func createAssetAssessmentWithRandomID(tx *gorm.DB, assessment *model.AssetAssessment) error {
	for attempt := 0; attempt < 3; attempt++ {
		identifier, err := commonid.New()
		if err != nil {
			return err
		}
		assessment.ID = identifier

		err = tx.Create(assessment).Error
		if err == nil {
			return nil
		}

		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) && platformdb.IsPrimaryKeyViolation(err) {
			continue
		}
		return err
	}

	return fmt.Errorf("exhausted random id retries for asset assessment")
}

// deleteOrphanedVulnerability removes a vulnerability when no assets still reference it.
func deleteOrphanedVulnerability(tx *gorm.DB, vulnerability model.Vulnerability) error {
	var count int64
	if err := tx.Model(&model.AssetVulnerability{}).
		Where("vulnerability_id = ? AND deleted_at IS NULL", vulnerability.ID).
		Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return tx.Delete(&vulnerability).Error
}

// setUpdatedBy records the authenticated user as the last updater when available.
func setUpdatedBy(ec *appcontext.GinContext, target *model.Model) {
	if ec == nil || target == nil {
		return
	}

	userID, err := ec.UserID()
	if err != nil {
		return
	}

	target.UpdatedByID = &userID
}

// optionalAssetString returns the pointed string value or an empty string.
func optionalAssetString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
