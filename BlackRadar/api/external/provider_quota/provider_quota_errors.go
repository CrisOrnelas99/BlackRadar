package providerquota

// ProviderQuotaError identifies a durable provider quota failure category.
type ProviderQuotaError struct {
	Message string
}

// Error returns the provider quota failure message.
func (e ProviderQuotaError) Error() string {
	return e.Message
}

var (
	// ErrExceeded indicates that the durable provider quota is exhausted.
	ErrExceeded = &ProviderQuotaError{Message: "provider quota exceeded"}
	// ErrUnavailable indicates that durable quota enforcement could not run.
	ErrUnavailable = &ProviderQuotaError{Message: "provider quota unavailable"}
)
