// Package service support contains validation, normalization, and refresh-session helpers for users.
package service

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	userrepository "blackradar/api/repository/user"
	auditservice "blackradar/api/service/audit"
)

// normalizeRegisterInput trims and lowercases registration fields before validation.
func normalizeRegisterInput(request RegisterInput) RegisterInput {
	request.FullName = strings.TrimSpace(request.FullName)
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Password = strings.TrimSpace(request.Password)
	return request
}

// validateRegisterInput validates the fields required to create an account.
func validateRegisterInput(request RegisterInput) error {
	if strings.TrimSpace(request.FullName) == "" || utf8.RuneCountInString(request.FullName) > 100 {
		return ErrInvalidRegisterRequest
	}
	if strings.TrimSpace(request.Username) == "" || utf8.RuneCountInString(request.Username) < 3 || utf8.RuneCountInString(request.Username) > 50 || strings.Contains(request.Username, "@") {
		return ErrInvalidRegisterRequest
	}
	if strings.TrimSpace(request.Password) == "" || utf8.RuneCountInString(request.Password) < 8 || utf8.RuneCountInString(request.Password) > 100 {
		return ErrInvalidRegisterRequest
	}
	if strings.TrimSpace(request.Email) == "" {
		return ErrInvalidRegisterRequest
	}
	parsedEmail, err := mail.ParseAddress(request.Email)
	if err != nil || parsedEmail.Address != request.Email {
		return fmt.Errorf("%w: invalid email", ErrInvalidRegisterRequest)
	}
	return nil
}

// isEmailLikeLoginIdentifier reports whether the login identifier should be treated as an email address.
func isEmailLikeLoginIdentifier(value string) bool {
	return strings.Contains(strings.TrimSpace(value), "@")
}

// translateUserRepositoryError maps repository errors to user service sentinels.
func translateUserRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, userrepository.ErrRecordNotFound):
		return fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	case errors.Is(err, userrepository.ErrUniqueViolation):
		return fmt.Errorf("%w: %w", ErrUsernameAlreadyExists, err)
	case errors.Is(err, userrepository.ErrNotNullViolation),
		errors.Is(err, userrepository.ErrForeignKeyViolation):
		return fmt.Errorf("%w: %w", ErrInvalidRegisterRequest, err)
	default:
		return fmt.Errorf("%w: %w", ErrUserDependency, err)
	}
}

// createRefreshSession stores a refresh token session for later rotation or logout.
func (s *userServiceImpl) createRefreshSession(ec *appcontext.GinContext, userID string, tokenID string, expiresAt time.Time) error {
	if s.auditService == nil {
		return translateUserRepositoryError(s.refreshSessionRepository.CreateRefreshSession(ec, model.RefreshSession{TokenID: tokenID, UserID: userID, DeviceName: requestDeviceName(ec), ExpiresAt: expiresAt}))
	}
	runner := s.transactionRunner
	if runner == nil {
		runner = platformdb.RequestTransactionRunner{}
	}
	return runner.Run(ec, func(txContext *appcontext.GinContext) error {
		if err := s.refreshSessionRepository.CreateRefreshSession(txContext, model.RefreshSession{TokenID: tokenID, UserID: userID, DeviceName: requestDeviceName(txContext), ExpiresAt: expiresAt}); err != nil {
			return translateUserRepositoryError(err)
		}
		return s.recordAudit(txContext, auditservice.EventInput{ActorUserID: &userID, Action: "auth.login", ResourceType: "user", ResourceID: &userID, Result: auditservice.ResultSucceeded})
	})
}

// rotateRefreshSession revokes the old refresh token session and stores the replacement.
func (s *userServiceImpl) rotateRefreshSession(ec *appcontext.GinContext, session model.RefreshSession, newTokenID string, expiresAt time.Time) error {
	newSession := model.RefreshSession{
		TokenID:    newTokenID,
		UserID:     session.UserID,
		DeviceName: session.DeviceName,
		ExpiresAt:  expiresAt,
	}

	if s.auditService == nil {
		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(ec, session.TokenID, session.UserID); err != nil {
			return translateUserRepositoryError(err)
		}
		return translateUserRepositoryError(s.refreshSessionRepository.CreateRefreshSession(ec, newSession))
	}
	runner := s.transactionRunner
	if runner == nil {
		runner = platformdb.RequestTransactionRunner{}
	}
	return runner.Run(ec, func(txContext *appcontext.GinContext) error {
		if err := s.refreshSessionRepository.RevokeByTokenIDForUser(txContext, session.TokenID, session.UserID); err != nil {
			return translateUserRepositoryError(err)
		}
		if err := s.refreshSessionRepository.CreateRefreshSession(txContext, newSession); err != nil {
			return translateUserRepositoryError(err)
		}
		return s.recordAudit(txContext, auditservice.EventInput{ActorUserID: &session.UserID, Action: "auth.refresh.rotate", ResourceType: "refresh_session", Result: auditservice.ResultSucceeded})
	})
}

// revokeAllRefreshSessionsForUser revokes every active refresh session for a user.
func (s *userServiceImpl) revokeAllRefreshSessionsForUser(ec *appcontext.GinContext, userID string) error {
	if s.auditService == nil {
		return s.refreshSessionRepository.RevokeActiveSessionsForUser(ec, userID)
	}
	runner := s.transactionRunner
	if runner == nil {
		runner = platformdb.RequestTransactionRunner{}
	}
	return runner.Run(ec, func(txContext *appcontext.GinContext) error {
		if err := s.refreshSessionRepository.RevokeActiveSessionsForUser(txContext, userID); err != nil {
			return translateUserRepositoryError(err)
		}
		return s.recordAudit(txContext, auditservice.EventInput{ActorUserID: &userID, Action: "auth.refresh.reuse", ResourceType: "refresh_session", Result: auditservice.ResultDenied})
	})
}

// recordAudit records an event when the caller has enabled durable auditing.
func (s *userServiceImpl) recordAudit(ec *appcontext.GinContext, input auditservice.EventInput) error {
	if s.auditService == nil {
		return nil
	}
	return s.auditService.Record(ec, input)
}

// requestDeviceName returns a bounded device label from the request user agent.
func requestDeviceName(ec *appcontext.GinContext) string {
	if ec == nil || ec.Context == nil || ec.Request == nil {
		return "unknown"
	}
	deviceName := strings.TrimSpace(ec.Request.UserAgent())
	if deviceName == "" {
		return "unknown"
	}
	if len(deviceName) > 255 {
		return deviceName[:255]
	}
	return deviceName
}
