// Package health coordinates application dependency readiness checks.
package health

import (
	"context"
	"sync"
	"time"

	nvdcveclient "blackradar/api/external/nvd_cve"
	textgeneration "blackradar/api/service/text_generation"
)

const (
	healthCheckCVEID              = "CVE-2021-44228"
	dependencyStatusCacheDuration = 30 * time.Second
	providerCheckTimeout          = 5 * time.Second
)

// Status is the safe readiness state exposed by the dependency summary.
type Status string

const (
	StatusHealthy       Status = "healthy"
	StatusUnavailable   Status = "unavailable"
	StatusNotConfigured Status = "not_configured"
)

// DatabaseChecker checks whether the database can serve requests.
type DatabaseChecker interface {
	// Ping checks the backing dependency and returns an error when it is unavailable.
	Ping(context.Context) error
}

// AIReadinessChecker verifies the configured provider with a backend-owned request.
type AIReadinessChecker interface {
	// TestProvider sends a fixed diagnostic request to the configured AI provider.
	TestProvider(context.Context) (textgeneration.TextGenerationResponse, error)
}

// NVDReadinessChecker verifies NVD availability with a backend-owned CVE lookup.
type NVDReadinessChecker interface {
	// LookupCVE retrieves the requested CVE or returns an external-provider error.
	LookupCVE(context.Context, string) (nvdcveclient.CVELookupResponse, error)
}

// Dependencies contains the backend-owned dependencies used by a health summary.
type Dependencies struct {
	Database     DatabaseChecker
	AIConfigured bool
	AI           AIReadinessChecker
	NVD          NVDReadinessChecker
}

// Summary is the dependency readiness result used by the health controller.
type Summary struct {
	Overall     Status
	Application Status
	Database    Status
	AI          Status
	NVD         Status
}

// SummaryChecker coordinates bounded dependency checks and provider-result caching.
type SummaryChecker struct {
	dependencies Dependencies
	cache        providerStatusCache
}

// NewSummaryChecker creates a dependency summary checker for the application runtime.
func NewSummaryChecker(dependencies Dependencies) *SummaryChecker {
	return &SummaryChecker{dependencies: dependencies}
}

// Check returns the current safe status for the application's dependencies.
func (s *SummaryChecker) Check(ctx context.Context) Summary {
	databaseStatus := StatusHealthy
	if s.dependencies.Database == nil || s.dependencies.Database.Ping(ctx) != nil {
		databaseStatus = StatusUnavailable
	}

	aiStatus, nvdStatus := s.cache.getOrCheck(ctx, s.dependencies)
	overallStatus := StatusHealthy
	if databaseStatus == StatusUnavailable || aiStatus == StatusUnavailable || nvdStatus == StatusUnavailable {
		overallStatus = StatusUnavailable
	}

	return Summary{
		Overall:     overallStatus,
		Application: StatusHealthy,
		Database:    databaseStatus,
		AI:          aiStatus,
		NVD:         nvdStatus,
	}
}

type providerStatusCache struct {
	mu          sync.Mutex
	expiresAt   time.Time
	aiStatus    Status
	nvdStatus   Status
	refreshing  bool
	refreshDone chan struct{}
}

func (c *providerStatusCache) getOrCheck(ctx context.Context, dependencies Dependencies) (Status, Status) {
	c.mu.Lock()
	if time.Now().Before(c.expiresAt) {
		aiStatus, nvdStatus := c.aiStatus, c.nvdStatus
		c.mu.Unlock()
		return aiStatus, nvdStatus
	}

	if c.refreshing {
		refreshDone := c.refreshDone
		c.mu.Unlock()

		select {
		case <-refreshDone:
			c.mu.Lock()
			aiStatus, nvdStatus := c.aiStatus, c.nvdStatus
			c.mu.Unlock()
			return aiStatus, nvdStatus
		case <-ctx.Done():
			return StatusUnavailable, StatusUnavailable
		}
	}

	c.refreshing = true
	c.refreshDone = make(chan struct{})
	refreshDone := c.refreshDone
	c.mu.Unlock()

	// Provider readiness is application-scoped, so it must not be cancelled when
	// the first browser request ends. Each provider still receives a strict timeout.
	checkContext := context.Background()
	aiStatus := checkAIProvider(checkContext, dependencies.AIConfigured, dependencies.AI)
	nvdStatus := checkNVDProvider(checkContext, dependencies.NVD)

	c.mu.Lock()
	c.aiStatus = aiStatus
	c.nvdStatus = nvdStatus
	c.expiresAt = time.Now().Add(dependencyStatusCacheDuration)
	c.refreshing = false
	close(refreshDone)
	c.mu.Unlock()

	return aiStatus, nvdStatus
}

func checkAIProvider(ctx context.Context, configured bool, checker AIReadinessChecker) Status {
	if !configured {
		return StatusNotConfigured
	}
	if checker == nil {
		return StatusUnavailable
	}

	aiContext, cancel := context.WithTimeout(ctx, providerCheckTimeout)
	defer cancel()
	if _, err := checker.TestProvider(aiContext); err == nil {
		return StatusHealthy
	}
	return StatusUnavailable
}

func checkNVDProvider(ctx context.Context, checker NVDReadinessChecker) Status {
	if checker == nil {
		return StatusUnavailable
	}

	nvdContext, cancel := context.WithTimeout(ctx, providerCheckTimeout)
	defer cancel()
	if _, err := checker.LookupCVE(nvdContext, healthCheckCVEID); err == nil {
		return StatusHealthy
	}
	return StatusUnavailable
}
