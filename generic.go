package jwt

import (
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// CustomClaims defines the interface for custom claims types.
// Types implementing this interface can be used with Processor methods that accept CustomClaims.
//
// Validation contract:
// For types other than *Claims, the Processor calls Validate() followed by
// registered claims string sanitization (length limits and injection pattern
// checks on Issuer, Subject, ID, Audience). Custom struct fields are NOT
// deeply validated — implementers are responsible for validating their own
// fields in the Validate() method.
//
// Example:
//
//	type MyClaims struct {
//		UserID string `json:"user_id"`
//		Role   string `json:"role"`
//		jwt.RegisteredClaims
//	}
//
//	func (c *MyClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
//		return &c.RegisteredClaims
//	}
//
//	func (c *MyClaims) Validate() error {
//		if c.UserID == "" {
//			return errors.New("user_id is required")
//		}
//		return nil
//	}
type CustomClaims interface {
	// GetRegisteredClaims returns a pointer to the embedded RegisteredClaims.
	// This allows the Processor to access standard JWT fields.
	GetRegisteredClaims() *RegisteredClaims

	// Validate performs custom validation on the claims.
	// Called after standard JWT validation (exp, nbf, iss) passes.
	Validate() error
}

// RateLimitKeyer is an optional interface that custom claims types can implement
// to provide a rate limit key when the Subject field is empty.
// If not implemented, rate limiting is skipped for requests with an empty Subject.
//
// Example:
//
//	func (c *MyClaims) RateLimitKey() string {
//	    return c.UserID
//	}
type RateLimitKeyer interface {
	RateLimitKey() string
}

// validateCustomClaims validates custom claims before token operations.
// Uses deep validation for built-in Claims, standard Validate() plus
// registered claims string sanitization for other types.
func validateCustomClaims(claims CustomClaims) error {
	if c, ok := claims.(*Claims); ok {
		// validateClaims covers all fields including registered claims strings
		if err := validateClaims(c); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidClaims, err)
		}
		return nil
	}
	if err := claims.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidClaims, err)
	}
	if err := validateRegisteredClaimsStrings(claims.GetRegisteredClaims()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidClaims, err)
	}
	return nil
}

// createTokenWithCustomClaims creates a signed token from custom claims.
// Caller must validate claims before calling this function.
func createTokenWithCustomClaims(p *Processor, claims CustomClaims, ttl time.Duration) (string, error) {
	rc := claims.GetRegisteredClaims()

	// Rate limit check with fallback: Subject → *Claims.UserID → RateLimitKeyer
	rateLimitKey := rc.Subject
	if rateLimitKey == "" {
		if c, ok := claims.(*Claims); ok {
			rateLimitKey = c.UserID
		} else if k, ok := claims.(RateLimitKeyer); ok {
			rateLimitKey = k.RateLimitKey()
		}
	}
	if err := p.checkRateLimit(rateLimitKey); err != nil {
		return "", err
	}

	// For *Claims, use pool copy to avoid mutating caller's struct
	if c, ok := claims.(*Claims); ok {
		claimsCopy := getClaims()
		defer putClaims(claimsCopy)
		copyClaims(claimsCopy, c)
		if err := p.setRegisteredDefaults(&claimsCopy.RegisteredClaims, ttl); err != nil {
			return "", err
		}
		return p.signClaims(claimsCopy)
	}

	// For other custom types, save and restore RegisteredClaims to avoid
	// mutating the caller's struct (consistent with built-in Claims behavior).
	orig := *rc
	defer func() { *rc = orig }()

	if err := p.setRegisteredDefaults(rc, ttl); err != nil {
		return "", err
	}
	return p.signClaims(claims)
}

// validateTokenIntoCustomClaims parses and validates a token into custom claims.
func validateTokenIntoCustomClaims(p *Processor, tokenString string, claims CustomClaims) error {
	token, err := p.parseToken(tokenString, claims)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	defer internal.ReleaseCore(token)

	if !token.Valid {
		return ErrInvalidToken
	}

	return p.validateRegistered(claims.GetRegisteredClaims())
}

// Ensure Claims implements CustomClaims interface.
var _ CustomClaims = (*Claims)(nil)

// GetRegisteredClaims returns the embedded RegisteredClaims.
// This implements the CustomClaims interface.
func (c *Claims) GetRegisteredClaims() *RegisteredClaims {
	return &c.RegisteredClaims
}

// Validate performs validation on the Claims.
// This implements the CustomClaims interface.
func (c *Claims) Validate() error {
	if c.UserID == "" && c.Username == "" {
		return ErrInvalidClaims
	}
	return nil
}
