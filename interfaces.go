package jwt

import (
	"time"
)

// TokenManager defines the core interface for JWT token operations.
// Implementations must be safe for concurrent use by multiple goroutines.
//
// This interface allows for dependency injection and easier testing.
// The default implementation is Processor.
type TokenManager interface {
	// CreateToken creates a new JWT token with the given claims.
	CreateToken(claims Claims) (string, error)

	// ValidateToken validates a JWT token and returns the claims.
	// Returns the claims, whether the token is valid, and any error.
	ValidateToken(tokenString string) (Claims, bool, error)

	// CreateRefreshToken creates a refresh token with the given claims.
	CreateRefreshToken(claims Claims) (string, error)

	// RefreshToken refreshes an existing refresh token and returns a new access token.
	RefreshToken(refreshTokenString string) (string, error)

	// RevokeToken adds a token to the blacklist.
	RevokeToken(tokenString string) error

	// IsTokenRevoked checks if a token has been revoked.
	IsTokenRevoked(tokenString string) (bool, error)

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

	// AllowN checks if n requests are allowed for the given key.
	AllowN(key string, n int) bool

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

// ExtendedTokenManager extends TokenManager with custom claims support.
// Use this interface when you need custom claims types beyond the built-in Claims.
type ExtendedTokenManager interface {
	TokenManager

	// CreateTokenWith creates a token with custom claims type.
	CreateTokenWith(claims CustomClaims) (string, error)

	// ValidateTokenFor validates a token and populates the provided custom claims.
	ValidateTokenFor(tokenString string, claims CustomClaims) (CustomClaims, bool, error)

	// CreateRefreshTokenWith creates a refresh token with custom claims type.
	CreateRefreshTokenWith(claims CustomClaims) (string, error)

	// RefreshTokenFor refreshes a custom-claims refresh token into a new access token.
	RefreshTokenFor(refreshTokenString string, claims CustomClaims) (string, error)
}

// Ensure Processor implements ExtendedTokenManager.
var _ ExtendedTokenManager = (*Processor)(nil)

// Ensure RateLimiter implements RateLimitProvider.
var _ RateLimitProvider = (*RateLimiter)(nil)

// Ensure SystemClock implements ClockProvider.
var _ ClockProvider = SystemClock{}

// Ensure FixedClock implements ClockProvider.
var _ ClockProvider = FixedClock{}
