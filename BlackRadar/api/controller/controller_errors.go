package controller

type ControllerError struct {
	Message string
}

func (e ControllerError) Error() string {
	return e.Message
}

var (
	ErrInvalidContentType    = &ControllerError{Message: "invalid content type"}
	ErrInvalidRequestBody    = &ControllerError{Message: "invalid request body"}
	ErrInvalidIdentifier     = &ControllerError{Message: "invalid identifier"}
	ErrInvalidRouteParameter = &ControllerError{Message: "invalid route parameter"}
)
