package jwt

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors for common failure cases.
// Use errors.Is() to check for specific error types.
var (
	// Configuration errors
	ErrInvalidConfig        = errors.New("invalid configuration")
	ErrInvalidSecretKey     = errors.New("invalid secret key")
	ErrInvalidSigningMethod = errors.New("invalid signing method")

	// Token errors
	ErrInvalidToken       = errors.New("invalid token")
	ErrEmptyToken         = errors.New("empty token")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrTokenMissingID     = errors.New("token missing ID")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenNotValidYet   = errors.New("token not valid yet")
	ErrTokenInvalidIssuer = errors.New("token invalid issuer")

	// Claims errors
	ErrInvalidClaims = errors.New("invalid claims")

	// Rate limiting errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// Lifecycle errors
	ErrProcessorClosed = errors.New("processor closed")
	ErrStoreClosed     = errors.New("store closed")
)

// ValidationError represents a field-level validation failure.
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

// TokenError represents a token-related error with additional context.
type TokenError struct {
	Err       error
	TokenID   string
	ExpiresAt time.Time
}

func (e *TokenError) Error() string {
	if e.TokenID != "" {
		return fmt.Sprintf("token error (id=%s): %v", e.TokenID, e.Err)
	}
	return fmt.Sprintf("token error: %v", e.Err)
}

func (e *TokenError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is interface for comparison.
func (e *TokenError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// SigningError represents a signing-related error.
// This error type is provided for applications that need to handle
// signing errors specifically. It can be used with custom signers
// or when implementing custom error handling logic.
type SigningError struct {
	Algorithm string
	Err       error
}

func (e *SigningError) Error() string {
	return fmt.Sprintf("signing error (alg=%s): %v", e.Algorithm, e.Err)
}

func (e *SigningError) Unwrap() error {
	return e.Err
}

// NewTokenError creates a new TokenError wrapping the given error.
func NewTokenError(err error, tokenID string, expiresAt time.Time) *TokenError {
	return &TokenError{
		Err:       err,
		TokenID:   tokenID,
		ExpiresAt: expiresAt,
	}
}

// NewSigningError creates a new SigningError for the given algorithm.
func NewSigningError(algorithm string, err error) *SigningError {
	return &SigningError{
		Algorithm: algorithm,
		Err:       err,
	}
}
