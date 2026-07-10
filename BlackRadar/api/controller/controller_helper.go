// Package controller provides shared HTTP helpers for the API.
package controller

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	appcontext "blackradar/api/context"
	"blackradar/api/dto"
)

const maxJSONBodyBytes int64 = 1 << 20

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// BindJSON parses an application/json request body into the provided destination.
func BindJSON(ec *appcontext.GinContext, destination any) bool {
	contentType := ec.GetHeader("Content-Type")
	if contentType == "" || !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		HandleError(ec, http.StatusUnsupportedMediaType, ErrInvalidContentType, "Content-Type must be application/json")
		return true
	}

	ec.Request.Body = http.MaxBytesReader(ec.Writer, ec.Request.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(ec.Request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		HandleError(ec, http.StatusBadRequest, errors.Join(ErrInvalidRequestBody, err), "Invalid request body")
		return true
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = ErrInvalidRequestBody
		}
		HandleError(ec, http.StatusBadRequest, err, "Invalid request body")
		return true
	}

	return false
}

// HandleError logs the request failure and writes a safe API error response.
func HandleError(ec *appcontext.GinContext, status int, err error, message string) bool {
	if err == nil {
		return false
	}

	ec.Logger().Error("request error", "status", status, "error", err, "message", message)
	ec.JSON(status, dto.ErrorResponse{
		Code:      errorCode(status),
		Message:   message,
		RequestID: ec.TransactionID(),
	})
	return true
}

// errorCode maps HTTP statuses to stable API error codes.
func errorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "VALIDATION_ERROR"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case http.StatusBadGateway:
		return "UPSTREAM_ERROR"
	case http.StatusUnsupportedMediaType:
		return "UNSUPPORTED_MEDIA_TYPE"
	default:
		return "INTERNAL_ERROR"
	}
}

// ParseID validates a path or query identifier as a positive integer.
func ParseID(value string) (string, error) {
	return parseID(value)
}

// ParsePair validates the asset and vulnerability identifiers from a request context.
func ParsePair(ec *appcontext.GinContext) (string, string, bool) {
	return parsePair(ec)
}

// parseID validates a UUID identifier.
func parseID(value string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(value))
	if !uuidPattern.MatchString(id) {
		return "", ErrInvalidIdentifier
	}
	return id, nil
}

// parsePair parses the asset and vulnerability identifiers from the request.
func parsePair(ec *appcontext.GinContext) (string, string, bool) {
	assetID, err := parseID(ec.Param("id"))
	if err != nil {
		return "", "", false
	}
	vulnerabilityID, err := parseID(ec.Param("vulnerabilityId"))
	if err != nil {
		return "", "", false
	}
	return assetID, vulnerabilityID, true
}
