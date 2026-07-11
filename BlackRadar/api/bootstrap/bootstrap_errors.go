package bootstrap

type BootstrapError struct {
	Message string
}

func (e BootstrapError) Error() string {
	return e.Message
}

var (
	ErrDatabaseRequired              = &BootstrapError{Message: "bootstrap dev data requires a database connection"}
	ErrBootstrapOrganizationConflict = &BootstrapError{Message: "bootstrap organization ID belongs to another organization"}
)
