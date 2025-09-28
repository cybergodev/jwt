package jwt

import (
	"errors"
	"fmt"
)

// Simplified error types - only essential errors
var (
	// Configuration errors
	ErrInvalidConfig        = errors.New("invalid configuration")
	ErrInvalidSecretKey     = errors.New("invalid secret key")
	ErrInvalidSigningMethod = errors.New("invalid signing method")

	// Token errors
	ErrInvalidToken = errors.New("invalid token")
	ErrEmptyToken   = errors.New("empty token")

	// Claims errors
	ErrInvalidClaims = errors.New("invalid claims")

	// System errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// ValidationError represents a simple validation error
type ValidationError struct {
	Field   string
	Message string
	Err     error
}

func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("validation failed for field '%s': %s: %v", e.Field, e.Message, e.Err)
	}
	return fmt.Sprintf("validation failed for field '%s': %s", e.Field, e.Message)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}
