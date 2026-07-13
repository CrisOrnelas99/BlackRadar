package permissions

type PermissionsError struct {
	Message string
}

func (e PermissionsError) Error() string {
	return e.Message
}

var (
	ErrForbidden      = &PermissionsError{Message: "forbidden"}
	ErrUnauthorized   = &PermissionsError{Message: "Unauthorized"}
	ErrInternalServer = &PermissionsError{Message: "internal server error"}
)
