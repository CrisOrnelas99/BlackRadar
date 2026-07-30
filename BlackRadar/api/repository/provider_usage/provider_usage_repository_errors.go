package providerusage

// ProviderUsageRepositoryError identifies a provider usage persistence failure category.
type ProviderUsageRepositoryError struct {
	Message string
}

// Error returns the provider usage persistence failure message.
func (e ProviderUsageRepositoryError) Error() string {
	return e.Message
}

var (
	ErrDatabaseRequired     = &ProviderUsageRepositoryError{Message: "database connection required"}
	ErrInvalidConfiguration = &ProviderUsageRepositoryError{Message: "invalid provider quota configuration"}
	ErrPersistenceFailure   = &ProviderUsageRepositoryError{Message: "provider usage persistence failure"}
)
