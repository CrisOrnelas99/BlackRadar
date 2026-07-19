package model

import (
	"encoding/json"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestTableNamesRemainStable(t *testing.T) {
	tests := []struct {
		name     string
		table    string
		expected string
	}{
		{name: "asset", table: Asset{}.TableName(), expected: "assets"},
		{name: "asset assessment", table: AssetAssessment{}.TableName(), expected: "asset_assessments"},
		{name: "asset vulnerability", table: AssetVulnerability{}.TableName(), expected: "asset_vulnerabilities"},
		{name: "refresh session", table: RefreshSession{}.TableName(), expected: "refresh_sessions"},
		{name: "user", table: User{}.TableName(), expected: "users"},
		{name: "vulnerability", table: Vulnerability{}.TableName(), expected: "vulnerabilities"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.table != tt.expected {
				t.Fatalf("expected table %q, got %q", tt.expected, tt.table)
			}
		})
	}
}

func TestModelConstantsRemainStable(t *testing.T) {
	expected := map[string]string{
		"role admin":       "admin",
		"role user":        "user",
		"cpe accepted":     "accepted",
		"cpe needs review": "needs_review",
		"cpe rejected":     "rejected",
	}
	actual := map[string]string{
		"role admin":       RoleAdmin,
		"role user":        RoleUser,
		"cpe accepted":     AssetCPEReviewStatusAccepted,
		"cpe needs review": AssetCPEReviewStatusNeedsReview,
		"cpe rejected":     AssetCPEReviewStatusRejected,
	}

	for name, expectedValue := range expected {
		t.Run(name, func(t *testing.T) {
			if actual[name] != expectedValue {
				t.Fatalf("expected %q, got %q", expectedValue, actual[name])
			}
		})
	}
}

func TestUserJSONRedactsSecurityFields(t *testing.T) {
	updatedByID := "00000000-0000-4000-8000-000000000007"
	user := User{
		Model: Model{
			ID:          "00000000-0000-4000-8000-000000000001",
			DeletedAt:   gorm.DeletedAt{Time: time.Now(), Valid: true},
			UpdatedByID: &updatedByID,
		},
		Username:     "analyst",
		Email:        "analyst@example.com",
		Role:         RoleUser,
		PasswordHash: "$2a$10$redacted",
	}

	encoded := mustMarshalObject(t, user)

	assertJSONHasKeys(t, encoded, "id", "username", "email", "role")
	assertJSONOmitsKeys(t, encoded, "organization_id", "organizationId", "password_hash", "passwordHash", "deletedAt", "updatedById")
}

func TestAssetJSONRedactsOwnershipAndAssessmentLinkage(t *testing.T) {
	assessmentID := "00000000-0000-4000-8000-000000000010"
	asset := Asset{
		Model:             Model{ID: "00000000-0000-4000-8000-000000000002"},
		UserID:            "00000000-0000-4000-8000-000000000001",
		AssetAssessmentID: &assessmentID,
		Name:              "Firewall",
		Type:              "network",
		Owner:             "security",
		Criticality:       "high",
	}

	encoded := mustMarshalObject(t, asset)

	assertJSONHasKeys(t, encoded, "id", "name", "type", "owner", "criticality")
	assertJSONOmitsKeys(t, encoded, "organization_id", "organizationId", "user_id", "userId", "assetAssessmentId", "assessment")
}

func TestVulnerabilityJSONRedactsOwnership(t *testing.T) {
	vulnerability := Vulnerability{
		Model:       Model{ID: "00000000-0000-4000-8000-000000000003"},
		UserID:      "00000000-0000-4000-8000-000000000001",
		CVEID:       "CVE-2026-0001",
		Title:       "Example vulnerability",
		Severity:    "high",
		Description: "example",
		Status:      "open",
	}

	encoded := mustMarshalObject(t, vulnerability)

	assertJSONHasKeys(t, encoded, "id", "cveId", "title", "severity", "description", "status")
	assertJSONOmitsKeys(t, encoded, "organization_id", "organizationId", "user_id", "userId")
}

func TestRefreshSessionJSONRedactsTokenAndRevocationState(t *testing.T) {
	revokedAt := time.Now()
	session := RefreshSession{
		TokenID:    "raw-session-token-id",
		UserID:     "00000000-0000-4000-8000-000000000001",
		DeviceName: "browser",
		RevokedAt:  &revokedAt,
		ExpiresAt:  time.Now().Add(time.Hour),
	}

	encoded := mustMarshalObject(t, session)

	assertJSONHasKeys(t, encoded, "deviceName", "expiresAt")
	assertJSONOmitsKeys(t, encoded, "token_id", "tokenId", "user_id", "userId", "revokedAt")
}

func TestAssetVulnerabilityJSONRedactsBridgeIdentifiers(t *testing.T) {
	bridge := AssetVulnerability{
		AssetID:         "00000000-0000-4000-8000-000000000002",
		VulnerabilityID: "00000000-0000-4000-8000-000000000003",
		DeletedAt:       gorm.DeletedAt{Time: time.Now(), Valid: true},
	}

	encoded := mustMarshalObject(t, bridge)

	assertJSONHasKeys(t, encoded, "createdAt")
	assertJSONOmitsKeys(t, encoded, "asset_id", "assetId", "vulnerability_id", "vulnerabilityId", "deletedAt")
}

func mustMarshalObject(t *testing.T, value any) map[string]any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal value: %v", err)
	}

	var encoded map[string]any
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatalf("failed to unmarshal encoded value: %v", err)
	}

	return encoded
}

func assertJSONHasKeys(t *testing.T, encoded map[string]any, keys ...string) {
	t.Helper()

	for _, key := range keys {
		if _, exists := encoded[key]; !exists {
			t.Fatalf("expected JSON key %q to be present in %#v", key, encoded)
		}
	}
}

func assertJSONOmitsKeys(t *testing.T, encoded map[string]any, keys ...string) {
	t.Helper()

	for _, key := range keys {
		if _, exists := encoded[key]; exists {
			t.Fatalf("expected JSON key %q to be omitted from %#v", key, encoded)
		}
	}
}
