package authorization

type AuthorizationRepositoryError struct {
	Message string
}

func (e AuthorizationRepositoryError) Error() string {
	return e.Message
}

var (
	ErrForbidden = &AuthorizationRepositoryError{Message: "forbidden"}
)
