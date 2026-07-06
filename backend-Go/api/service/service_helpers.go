// Package service provides validation, context, and repository error helpers for application services.
package service

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/model"
	baserepository "secureops/backend-go/api/repository"
)

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
var aiPromptInjectionPattern = regexp.MustCompile(`(?i)(ignore (all )?previous instructions|system prompt|developer message|reveal the prompt|bypass policy|prompt injection|jailbreak|do anything now)`)

const aiIngestionMaxBytes = 8192
const aiIngestionMaxRunes = 4000

var displayAcronyms = map[string]string{
	"api":   "API",
	"aws":   "AWS",
	"cpe":   "CPE",
	"cve":   "CVE",
	"cpu":   "CPU",
	"dns":   "DNS",
	"http":  "HTTP",
	"https": "HTTPS",
	"id":    "ID",
	"iot":   "IoT",
	"ip":    "IP",
	"it":    "IT",
	"nvd":   "NVD",
	"os":    "OS",
	"sql":   "SQL",
	"ssh":   "SSH",
	"tls":   "TLS",
	"ui":    "UI",
	"url":   "URL",
	"vm":    "VM",
}

// TranslateRepositoryError maps repository errors to service-layer sentinels.
func TranslateRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, baserepository.ErrAssetNotFound), errors.Is(err, baserepository.ErrVulnerabilityNotFound), errors.Is(err, baserepository.ErrRefreshSessionNotFound):
		return wrapRepositoryError(ErrNotFound, err)
	case errors.Is(err, baserepository.ErrDuplicateData), errors.Is(err, baserepository.ErrDuplicateAssignment):
		return wrapRepositoryError(ErrConflict, err)
	case errors.Is(err, baserepository.ErrInvalidData), errors.Is(err, baserepository.ErrInvalidReference):
		return wrapRepositoryError(ErrInvalidRequestData, err)
	default:
		return wrapRepositoryError(ErrInternal, err)
	}
}

func wrapRepositoryError(serviceErr error, repositoryErr error) error {
	return fmt.Errorf("%w: %w", serviceErr, repositoryErr)
}

// ValidateAsset validates the fields required to create or update an asset.
func ValidateAsset(asset model.Asset) error {
	if strings.TrimSpace(asset.Name) == "" || strings.TrimSpace(asset.Type) == "" || strings.TrimSpace(asset.Owner) == "" || strings.TrimSpace(asset.Criticality) == "" {
		return ErrInvalidRequestData
	}
	return nil
}

// NormalizeDisplayText trims, title-cases, and preserves known acronyms for human-facing labels.
func NormalizeDisplayText(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	words := strings.Fields(trimmed)
	for index, word := range words {
		words[index] = normalizeDisplayWord(word)
	}

	return strings.Join(words, " ")
}

// NormalizeOptionalDisplayText normalizes an optional human-facing label while preserving nil for empty values.
func NormalizeOptionalDisplayText(value *string) *string {
	if value == nil {
		return nil
	}

	normalized := NormalizeDisplayText(*value)
	if normalized == "" {
		return nil
	}

	return &normalized
}

func normalizeDisplayWord(word string) string {
	if word == "" {
		return ""
	}

	lower := strings.ToLower(word)
	if acronym, ok := displayAcronyms[lower]; ok {
		return acronym
	}
	if isAllUpper(word) {
		return word
	}
	if hasMixedCase(word) {
		return word
	}

	runes := []rune(lower)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

func isAllUpper(value string) bool {
	hasLetter := false
	for _, r := range value {
		if !unicode.IsLetter(r) {
			continue
		}
		hasLetter = true
		if unicode.IsLower(r) {
			return false
		}
	}
	return hasLetter
}

func hasMixedCase(value string) bool {
	hasUpper := false
	hasLower := false
	for _, r := range value {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
	}
	return hasUpper && hasLower
}

// AuthenticatedUserID returns the authenticated user ID from the request context.
func AuthenticatedUserID(ec *appcontext.GinContext) (int64, error) {
	if ec == nil {
		return 0, ErrForbidden
	}

	userID := ec.UserID()
	if userID <= 0 {
		return 0, ErrForbidden
	}

	return userID, nil
}

// AuthenticatedOrganizationID returns the authenticated organization ID from the request context.
func AuthenticatedOrganizationID(ec *appcontext.GinContext) (int64, error) {
	if ec == nil {
		return 0, ErrForbidden
	}

	organizationID := ec.OrganizationID()
	if organizationID <= 0 {
		return 0, ErrForbidden
	}

	return organizationID, nil
}

// NormalizeRegisterRequest trims and normalizes registration input.
func NormalizeRegisterRequest(request dto.RegisterRequest) dto.RegisterRequest {
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Organization = strings.TrimSpace(request.Organization)
	request.Password = strings.TrimSpace(request.Password)
	return request
}

// ValidateRegisterRequest validates the fields required to create an account.
func ValidateRegisterRequest(request dto.RegisterRequest) error {
	if strings.TrimSpace(request.Username) == "" || utf8.RuneCountInString(request.Username) < 3 || utf8.RuneCountInString(request.Username) > 50 || strings.Contains(request.Username, "@") {
		return ErrInvalidRequestData
	}
	if strings.TrimSpace(request.Password) == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		return ErrInvalidRequestData
	}
	if strings.TrimSpace(request.Email) == "" {
		return ErrInvalidRequestData
	}
	if strings.TrimSpace(request.Organization) == "" || utf8.RuneCountInString(request.Organization) < 3 || utf8.RuneCountInString(request.Organization) > 80 {
		return ErrInvalidRequestData
	}
	if _, err := mail.ParseAddress(request.Email); err != nil {
		return fmt.Errorf("%w: invalid email", ErrInvalidRequestData)
	}
	return nil
}

// IsEmailLikeLoginIdentifier reports whether the supplied login identifier should be treated as an email address.
func IsEmailLikeLoginIdentifier(value string) bool {
	return strings.Contains(strings.TrimSpace(value), "@")
}

// ValidateVulnerability validates the fields required to create or update a vulnerability.
func ValidateVulnerability(vulnerability model.Vulnerability) error {
	if strings.TrimSpace(vulnerability.CVEID) == "" || strings.TrimSpace(vulnerability.Title) == "" || strings.TrimSpace(vulnerability.Severity) == "" || strings.TrimSpace(vulnerability.Description) == "" || strings.TrimSpace(vulnerability.Status) == "" {
		return ErrInvalidRequestData
	}
	return nil
}

// NormalizeCVEID trims and uppercases a CVE identifier before lookup.
func NormalizeCVEID(cveID string) string {
	return strings.ToUpper(strings.TrimSpace(cveID))
}

// NormalizeSeverity converts external severity strings into the app's canonical title-case form.
func NormalizeSeverity(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "":
		return ""
	case "low":
		return "Low"
	case "medium":
		return "Medium"
	case "high":
		return "High"
	case "critical":
		return "Critical"
	default:
		return strings.ToUpper(strings.TrimSpace(value))
	}
}

// ValidateCVEID verifies the identifier is safe to use with the NVD CVE API.
func ValidateCVEID(cveID string) error {
	if !cveIDPattern.MatchString(NormalizeCVEID(cveID)) {
		return ErrInvalidRequestData
	}
	return nil
}

// SanitizeAIIngestionText normalizes pasted asset text and rejects obvious prompt-injection attempts.
func SanitizeAIIngestionText(rawText string) (string, error) {
	if !utf8.ValidString(rawText) {
		return "", ErrInvalidRequestData
	}

	trimmed := strings.TrimSpace(rawText)
	if trimmed == "" {
		return "", ErrInvalidRequestData
	}
	if len(trimmed) > aiIngestionMaxBytes || utf8.RuneCountInString(trimmed) > aiIngestionMaxRunes {
		return "", ErrInvalidRequestData
	}
	if aiPromptInjectionPattern.MatchString(trimmed) {
		return "", ErrInvalidRequestData
	}

	normalized := strings.ReplaceAll(trimmed, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	normalized = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\t':
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, normalized)

	lines := strings.Split(normalized, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(strings.Join(strings.Fields(line), " "))
	}

	return strings.TrimSpace(strings.Join(lines, "\n")), nil
}
