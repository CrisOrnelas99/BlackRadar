package health

import (
	"context"
	"testing"
	"time"

	nvdcveclient "blackradar/api/external/nvd_cve"
	textgeneration "blackradar/api/service/text_generation"
)

func TestSummaryCheckerCompletesProviderRefreshAfterRequesterCancellation(t *testing.T) {
	aiChecker := &blockingAIReadinessChecker{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	checker := NewSummaryChecker(Dependencies{
		Database:     healthyDatabaseChecker{},
		AIConfigured: true,
		AI:           aiChecker,
		NVD:          healthyNVDReadinessChecker{},
	})

	requestContext, cancel := context.WithCancel(context.Background())
	result := make(chan Summary, 1)
	go func() {
		result <- checker.Check(requestContext)
	}()

	<-aiChecker.started
	cancel()

	select {
	case summary := <-result:
		t.Fatalf("expected provider refresh to outlive requester cancellation, got AI status %q", summary.AI)
	case <-time.After(25 * time.Millisecond):
	}

	close(aiChecker.release)
	summary := <-result
	if summary.AI != StatusHealthy || summary.NVD != StatusHealthy {
		t.Fatalf("expected healthy provider statuses, got AI=%q NVD=%q", summary.AI, summary.NVD)
	}

	cachedSummary := checker.Check(context.Background())
	if cachedSummary.AI != StatusHealthy || aiChecker.calls != 1 {
		t.Fatalf("expected one cached healthy AI check, got status=%q calls=%d", cachedSummary.AI, aiChecker.calls)
	}
}

type healthyDatabaseChecker struct{}

func (healthyDatabaseChecker) Ping(context.Context) error {
	return nil
}

type healthyNVDReadinessChecker struct{}

func (healthyNVDReadinessChecker) LookupCVE(context.Context, string) (nvdcveclient.CVELookupResponse, error) {
	return nvdcveclient.CVELookupResponse{}, nil
}

type blockingAIReadinessChecker struct {
	started chan struct{}
	release chan struct{}
	calls   int
}

func (c *blockingAIReadinessChecker) TestProvider(ctx context.Context) (textgeneration.TextGenerationResponse, error) {
	c.calls++
	close(c.started)

	select {
	case <-c.release:
		return textgeneration.TextGenerationResponse{}, nil
	case <-ctx.Done():
		return textgeneration.TextGenerationResponse{}, ctx.Err()
	}
}
