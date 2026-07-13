package ratelimit

type RateLimitError struct {
	Message string
}

func (e RateLimitError) Error() string {
	return e.Message
}

var (
	ErrRateLimited               = &RateLimitError{Message: "Rate limit exceeded."}
	ErrRateLimitNameRequired     = &RateLimitError{Message: "rate limit rule name is required"}
	ErrInvalidRateLimit          = &RateLimitError{Message: "rate limit must be greater than zero"}
	ErrInvalidRateLimitWindow    = &RateLimitError{Message: "rate limit window must be greater than zero"}
	ErrInvalidRateLimitCleanup   = &RateLimitError{Message: "rate-limit cleanup interval cannot be negative"}
	ErrInvalidRateLimitRetention = &RateLimitError{Message: "rate-limit entry retention cannot be negative"}
)
