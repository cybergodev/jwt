package jwt

import (
	"errors"
	"fmt"
)

// Predefined errors for common JWT operations
var (
	// Configuration errors
	ErrInvalidConfig        = errors.New("invalid configuration")
	ErrInvalidSecretKey     = errors.New("invalid secret key: must be at least 32 bytes with sufficient entropy")
	ErrInvalidSigningMethod = errors.New("invalid signing method: must be HS256, HS384, or HS512")

	// Token errors
	ErrInvalidToken   = errors.New("invalid token: signature verification failed or malformed")
	ErrEmptyToken     = errors.New("empty token: token string cannot be empty")
	ErrTokenRevoked   = errors.New("token has been revoked and is no longer valid")
	ErrTokenMissingID = errors.New("token does not contain a valid ID (jti claim)")

	// Claims errors
	ErrInvalidClaims = errors.New("invalid claims: UserID or Username is required")

	// System errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded: too many requests")
	ErrProcessorClosed   = errors.New("processor is closed: cannot perform operations")
)

// ValidationError represents a validation error for a specific field.
// It provides detailed information about what validation failed and why.
type ValidationError struct {
	Field   string // The field that failed validation
	Message string // Human-readable error message
	Err     error  // Underlying error, if any
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
