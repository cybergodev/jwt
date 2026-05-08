package jwt

import (
	"time"
)

// TokenManager defines the core interface for JWT token operations.
// Implementations must be safe for concurrent use by multiple goroutines.
//
// This interface allows for dependency injection and easier testing.
// The default implementation is Processor.
//
// Consumers: define your own smaller interface with only the methods you need.
// For example, if you only need Create and Validate:
//
//	type TokenCreator interface {
//	    Create(claims jwt.CustomClaims) (string, error)
//	    Validate(tokenString string) (jwt.Claims, bool, error)
//	}
//
// Methods are organized into three groups:
//   - Token Operations: Create, CreateRefresh (both accept CustomClaims)
//   - Validation & Refresh: Validate, ValidateInto, Refresh, RefreshInto
//   - Common: Revoke, IsRevoked, ParseUnverified, Close, IsClosed
type TokenManager interface {
	// Create creates a new JWT access token with the given claims.
	// Accepts any type implementing CustomClaims, including *Claims.
	Create(claims CustomClaims) (string, error)

	// Validate validates a JWT access token and returns the parsed Claims.
	// Returns a value copy of the claims, whether the token is valid, and any error.
	Validate(tokenString string) (Claims, bool, error)

	// CreateRefresh creates a refresh token with the given claims.
	// Accepts any type implementing CustomClaims, including *Claims.
	CreateRefresh(claims CustomClaims) (string, error)

	// Refresh refreshes an existing refresh token and returns a new access token.
	Refresh(refreshTokenString string) (string, error)

	// ValidateInto validates a token and populates the provided custom claims.
	ValidateInto(tokenString string, claims CustomClaims) (CustomClaims, bool, error)

	// RefreshInto refreshes a custom-claims refresh token into a new access token.
	RefreshInto(refreshTokenString string, claims CustomClaims) (string, error)

	// Revoke adds a token to the blacklist.
	Revoke(tokenString string) error

	// IsRevoked checks if a token has been revoked.
	IsRevoked(tokenString string) (bool, error)

	// ParseUnverified parses a token without verifying the signature.
	// WARNING: The returned claims are NOT validated and should NOT be trusted.
	ParseUnverified(tokenString string, claims any) error

	// Close releases resources and securely clears sensitive data.
	Close() error

	// IsClosed returns whether the manager has been closed.
	IsClosed() bool
}

// RateLimitProvider defines the interface for rate limiting.
// Implementations must be safe for concurrent use by multiple goroutines.
type RateLimitProvider interface {
	// Allow checks if a single request is allowed for the given key.
	Allow(key string) bool

	// Reset removes the rate limit state for the given key.
	Reset(key string)

	// Close releases resources used by the rate limiter.
	Close()
}

// ClockProvider defines the interface for time operations.
// This allows for time injection in tests and more flexible time handling.
type ClockProvider interface {
	// Now returns the current time.
	Now() time.Time
}

// SystemClock is the default ClockProvider using system time.
type SystemClock struct{}

// Now returns the current system time.
func (SystemClock) Now() time.Time {
	return time.Now()
}

// FixedClock is a ClockProvider that returns a fixed time.
// Useful for testing.
type FixedClock struct {
	T time.Time
}

// Now returns the fixed time.
func (c FixedClock) Now() time.Time {
	return c.T
}

// Ensure Processor implements TokenManager.
var _ TokenManager = (*Processor)(nil)

// Ensure RateLimiter implements RateLimitProvider.
var _ RateLimitProvider = (*RateLimiter)(nil)

// Ensure SystemClock implements ClockProvider.
var _ ClockProvider = SystemClock{}

// Ensure FixedClock implements ClockProvider.
var _ ClockProvider = FixedClock{}
