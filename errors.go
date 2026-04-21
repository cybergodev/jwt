package jwt

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure cases.
// Use errors.Is() to check for specific error types.
var (
	// ErrInvalidConfig indicates that the provided configuration is invalid.
	ErrInvalidConfig = errors.New("invalid configuration")
	// ErrInvalidSecretKey indicates that the signing key is missing, too short, or too weak.
	ErrInvalidSecretKey = errors.New("invalid secret key")
	// ErrInvalidSigningMethod indicates that the signing method is not recognized or not supported.
	ErrInvalidSigningMethod = errors.New("invalid signing method")

	// ErrInvalidToken indicates that the token could not be parsed or has an invalid signature.
	ErrInvalidToken = errors.New("invalid token")
	// ErrEmptyToken indicates that an empty token string was provided.
	ErrEmptyToken = errors.New("empty token")
	// ErrAlgorithmMismatch indicates that the token's algorithm header does not match the configured signing method.
	ErrAlgorithmMismatch = errors.New("token algorithm does not match configured signing method")
	// ErrTokenRevoked indicates that the token has been revoked via the blacklist.
	ErrTokenRevoked = errors.New("token revoked")
	// ErrTokenMissingID indicates that the token does not contain a jti (JWT ID) claim required for blacklist operations.
	ErrTokenMissingID = errors.New("token missing ID")
	// ErrTokenExpired indicates that the token's exp (expiration) claim has passed.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenNotValidYet indicates that the token's nbf (not-before) claim is in the future.
	ErrTokenNotValidYet = errors.New("token not valid yet")
	// ErrTokenInvalidIssuer indicates that the token's iss (issuer) claim does not match the configured issuer.
	ErrTokenInvalidIssuer = errors.New("token invalid issuer")
	// ErrTokenInvalidAudience indicates that the token's aud (audience) claim does not match the configured audience.
	ErrTokenInvalidAudience = errors.New("token invalid audience")

	// ErrInvalidClaims indicates that the claims failed validation (missing required fields, injection patterns, etc.).
	ErrInvalidClaims = errors.New("invalid claims")

	// ErrRateLimitExceeded indicates that the rate limit for token operations has been exceeded.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// ErrBlacklistNotConfigured indicates that a blacklist operation was attempted without configuring the blacklist.
	ErrBlacklistNotConfigured = errors.New("blacklist not configured")

	// ErrProcessorClosed indicates that an operation was attempted on a closed Processor.
	ErrProcessorClosed = errors.New("processor closed")
	// ErrStoreClosed indicates that an operation was attempted on a closed store.
	ErrStoreClosed = errors.New("store closed")
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
