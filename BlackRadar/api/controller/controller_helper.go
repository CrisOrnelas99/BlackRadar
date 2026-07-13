// Package controller provides shared HTTP helpers for the API.
package controller

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	appcontext "blackradar/api/context"
	"blackradar/api/controller/dto"
	baseservice "blackradar/api/service"
)

const maxJSONBodyBytes int64 = 1 << 20

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// BindJSON parses an application/json request body into the provided destination.
func BindJSON(ec *appcontext.GinContext, destination any) bool {
	if !isJSONContentType(ec.GetHeader("Content-Type")) {
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

func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/json")
}

// ServiceErrorMessages customizes safe client messages for service errors.
type ServiceErrorMessages struct {
	InvalidRequest     string
	Conflict           string
	NotFound           string
	InvalidCredentials string
	Forbidden          string
	RateLimited        string
	ExternalService    string
}

// HandleServiceError maps service-layer sentinels to safe HTTP responses.
func HandleServiceError(ec *appcontext.GinContext, err error, messages ServiceErrorMessages) bool {
	var serviceErr *baseservice.ServiceError
	if !errors.As(err, &serviceErr) {
		return false
	}

	switch {
	case errors.Is(err, baseservice.ErrInvalidRequestData):
		HandleError(ec, http.StatusBadRequest, err, firstNonEmpty(messages.InvalidRequest, baseservice.ErrInvalidRequestData.Error()))
	case errors.Is(err, baseservice.ErrConflict):
		HandleError(ec, http.StatusConflict, err, firstNonEmpty(messages.Conflict, baseservice.ErrConflict.Error()))
	case errors.Is(err, baseservice.ErrNotFound):
		HandleError(ec, http.StatusNotFound, err, firstNonEmpty(messages.NotFound, baseservice.ErrNotFound.Error()))
	case errors.Is(err, baseservice.ErrInvalidCredentials):
		HandleError(ec, http.StatusUnauthorized, err, firstNonEmpty(messages.InvalidCredentials, baseservice.ErrInvalidCredentials.Error()))
	case errors.Is(err, baseservice.ErrForbidden):
		HandleError(ec, http.StatusForbidden, err, firstNonEmpty(messages.Forbidden, baseservice.ErrForbidden.Error()))
	case errors.Is(err, baseservice.ErrRateLimited):
		HandleError(ec, http.StatusTooManyRequests, err, firstNonEmpty(messages.RateLimited, baseservice.ErrRateLimited.Error()))
	case errors.Is(err, baseservice.ErrExternalService):
		HandleError(ec, http.StatusBadGateway, err, firstNonEmpty(messages.ExternalService, "External service unavailable"))
	default:
		HandleError(ec, http.StatusInternalServerError, err, baseservice.ErrInternal.Error())
	}

	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
		RequestID: ec.RequestID(),
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

// ParseID validates a path or query identifier as a UUID.
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
