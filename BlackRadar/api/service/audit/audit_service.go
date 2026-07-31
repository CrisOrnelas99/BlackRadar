// Package audit provides security audit-event application services.
package audit

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
	auditrepository "blackradar/api/repository/audit"
)

const (
	ResultSucceeded = "succeeded"
	ResultDenied    = "denied"
)

// EventInput contains the safe, server-derived facts to persist for one event.
type EventInput struct {
	ActorUserID  *string
	Action       string
	ResourceType string
	ResourceID   *string
	Result       string
	Details      string
}

// auditServiceImpl records validated events through the audit repository.
type auditServiceImpl struct {
	repository auditrepository.RepositoryInterface
}

// NewService creates an audit service backed by the supplied repository.
func NewService(repository auditrepository.RepositoryInterface) *auditServiceImpl {
	return &auditServiceImpl{repository: repository}
}

// Record validates and persists one append-only audit event.
func (s *auditServiceImpl) Record(ec *appcontext.GinContext, input EventInput) error {
	if s == nil || s.repository == nil || ec == nil || strings.TrimSpace(ec.RequestID()) == "" {
		return ErrUnavailable
	}
	input.Action = strings.TrimSpace(input.Action)
	input.ResourceType = strings.TrimSpace(input.ResourceType)
	input.Result = strings.TrimSpace(input.Result)
	input.Details = strings.TrimSpace(input.Details)
	if input.Action == "" || input.ResourceType == "" || (input.Result != ResultSucceeded && input.Result != ResultDenied) || !utf8.ValidString(input.Details) || utf8.RuneCountInString(input.Details) > 256 || strings.ContainsAny(input.Details, "\r\n") {
		return ErrInvalidEvent
	}
	if err := s.repository.Create(ec, model.AuditEvent{
		RequestID:    ec.RequestID(),
		ActorUserID:  input.ActorUserID,
		Action:       input.Action,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		Result:       input.Result,
		Details:      input.Details,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return nil
}

var _ Service = (*auditServiceImpl)(nil)
