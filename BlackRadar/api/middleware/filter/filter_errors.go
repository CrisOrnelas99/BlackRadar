package filter

type FilterError struct {
	Message string
}

func (e FilterError) Error() string {
	return e.Message
}

var (
	ErrInvalidRequestPath     = &FilterError{Message: "invalid request path"}
	ErrRequestPathTooLong     = &FilterError{Message: "request path exceeds maximum length"}
	ErrRequestPathControlChar = &FilterError{Message: "request path contains a control character"}
	ErrRequestPathBadEncoding = &FilterError{Message: "request path contains malformed encoding"}
	ErrRequestPathTraversal   = &FilterError{Message: "request path contains traversal segments"}
)
