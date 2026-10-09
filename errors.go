package jwt

import (
	"errors"
	"fmt"

	"github.com/cybergodev/jwt/internal"
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
	// Aliased to the internal sentinel (same message) so errors.Is matches
	// across the parse layer and the public API, mirroring ErrStoreClosed.
	ErrAlgorithmMismatch = internal.ErrAlgorithmMismatch
	// ErrTokenRevoked indicates that the token has been revoked via the blacklist.
	ErrTokenRevoked = errors.New("token revoked")
	// ErrTokenMissingID indicates that the token does not contain a jti (JWT ID) claim required for blacklist operations.
	ErrTokenMissingID = errors.New("token missing ID")
	// ErrTokenTypeMismatch indicates that a refresh operation received a token of the wrong type.
	ErrTokenTypeMismatch = errors.New("token type mismatch")
	// ErrRefreshRotationFailed indicates that Config.RotateRefreshTokens is
	// enabled and revoking the supplied refresh token failed before a new
	// token could be minted; no new token was issued. Wraps the underlying
	// blacklist store error.
	ErrRefreshRotationFailed = errors.New("refresh rotation failed")
	// ErrTokenExpired indicates that the token's exp (expiration) claim has passed.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenNotValidYet indicates that the token's nbf (not-before) claim is in the future.
	ErrTokenNotValidYet = errors.New("token not valid yet")
	// ErrTokenInvalidIssuer indicates that the token's iss (issuer) claim does not match the configured issuer.
	ErrTokenInvalidIssuer = errors.New("token invalid issuer")
	// ErrTokenInvalidAudience indicates that the token's aud (audience) claim does not match the configured audience.
	ErrTokenInvalidAudience = errors.New("token invalid audience")
	// ErrExpirationRequired indicates that the token lacks an exp claim while
	// RequireExpiration is enabled. Such tokens would otherwise never expire.
	ErrExpirationRequired = errors.New("token missing expiration claim")

	// ErrInvalidClaims indicates that the claims failed validation (missing required fields, injection patterns, etc.).
	ErrInvalidClaims = errors.New("invalid claims")

	// ErrRateLimitExceeded indicates that the rate limit for token operations has been exceeded.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// ErrBlacklistNotConfigured indicates that a blacklist operation was attempted without configuring the blacklist.
	ErrBlacklistNotConfigured = errors.New("blacklist not configured")

	// ErrProcessorClosed indicates that an operation was attempted on a closed
	// or nil Processor. All Processor methods are nil-receiver safe and report
	// this sentinel instead of panicking.
	ErrProcessorClosed = errors.New("processor closed")
	// ErrStoreClosed indicates that an operation was attempted on a closed store.
	ErrStoreClosed = internal.ErrStoreClosed
)

// ValidationError represents a field-level validation failure.
type ValidationError struct {
	// Field is the name of the field or claim that failed validation
	// (e.g. "user_id", "extra.color", "audience").
	Field string

	// Message describes why the field is invalid
	// (e.g. "exceeds maximum length of 256", "suspicious pattern detected").
	Message string

	// Err is an optional underlying error wrapped by this validation failure.
	// Unwrap returns it, so errors.Is and errors.As traverse it.
	// May be nil when the failure has no wrapped cause.
	Err error
}

// Error returns a human-readable description of the validation failure,
// including the field name, message, and wrapped error (if any).
// This implements the error interface.
func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("validation failed for field '%s': %s: %v", e.Field, e.Message, e.Err)
	}
	return fmt.Sprintf("validation failed for field '%s': %s", e.Field, e.Message)
}

// Unwrap returns the wrapped error stored in Err, enabling errors.Is and
// errors.As to reach an underlying cause. It returns nil when Err is unset.
func (e *ValidationError) Unwrap() error {
	return e.Err
}
