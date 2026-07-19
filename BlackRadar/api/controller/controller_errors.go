package controller

// ControllerError represents an HTTP-layer error that occurs before service logic runs.
type ControllerError struct {
	Message string
}

// Error returns the safe controller error message.
func (e ControllerError) Error() string {
	return e.Message
}

var (
	ErrInvalidContentType = &ControllerError{Message: "invalid content type"}
	ErrInvalidRequestBody = &ControllerError{Message: "invalid request body"}
	ErrInvalidIdentifier  = &ControllerError{Message: "invalid identifier"}
)
