package providerquota

import (
	"context"
	"time"
)

// Reserver atomically reserves one provider request in a shared quota window.
type Reserver interface {
	/*
		Reserve records one attempted outbound request or returns an error.

		Implementations must enforce the limit atomically across application
		instances and fail closed when the backing store is unavailable.
	*/
	Reserve(ctx context.Context, provider string, now time.Time, limit int, window time.Duration) error
}
