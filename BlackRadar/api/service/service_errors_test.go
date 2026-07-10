// Package service verifies service-level sentinel errors.
package service

import "testing"

// TestServiceSentinels verifies the core service sentinel messages.
func TestServiceSentinels(t *testing.T) {
	if ErrInvalidRequestData.Error() != "invalid request data" {
		t.Fatal("unexpected sentinel message")
	}
	if ErrRateLimited.Error() != "rate limited" {
		t.Fatal("unexpected rate-limited sentinel message")
	}
	if ErrExternalService.Error() != "external service unavailable" {
		t.Fatal("unexpected external-service sentinel message")
	}
}
