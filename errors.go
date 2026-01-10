package jwt

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidConfig        = errors.New("invalid configuration")
	ErrInvalidSecretKey     = errors.New("invalid secret key")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	ErrInvalidToken         = errors.New("invalid token")
	ErrEmptyToken           = errors.New("empty token")
	ErrTokenRevoked         = errors.New("token revoked")
	ErrTokenMissingID       = errors.New("token missing ID")
	ErrInvalidClaims        = errors.New("invalid claims")
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
	ErrProcessorClosed      = errors.New("processor closed")
)

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
