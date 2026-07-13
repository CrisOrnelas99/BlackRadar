package cors

type CORSError struct {
	Message string
}

func (e CORSError) Error() string {
	return e.Message
}

var (
	ErrInvalidCORSOrigin  = &CORSError{Message: "invalid CORS origin"}
	ErrCORSWildcardOrigin = &CORSError{Message: "CORS wildcard origin is not allowed"}
	ErrCORSNullOrigin     = &CORSError{Message: `CORS origin "null" is not allowed`}
	ErrInvalidCORSMaxAge  = &CORSError{Message: "CORS max age cannot be negative"}
)
