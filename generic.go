package jwt

import (
	"errors"
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

// requireNonNilClaims rejects a nil claims value — either a nil interface or
// a typed-nil *Claims, which boxes as a non-nil CustomClaims yet would
// nil-panic on the first pointer-receiver method call. Shared by the create
// paths (via validateCustomClaims) and the *Into parse paths so every
// entry point reports the same ErrInvalidClaims for the same misuse.
// Typed-nil values of other custom types are not detectable here without
// reflection; for them the parse pipeline's json.Unmarshal rejects a nil
// destination with *InvalidUnmarshalError, and FastUnmarshaler implementations
// are contractually required to return an error rather than panic on a nil
// receiver (see the interface documentation in internal/encoding.go).
func requireNonNilClaims(claims CustomClaims) error {
	if claims == nil {
		return fmt.Errorf("%w: claims must not be nil", ErrInvalidClaims)
	}
	if c, ok := claims.(*Claims); ok && c == nil {
		return fmt.Errorf("%w: claims must not be nil", ErrInvalidClaims)
	}
	return nil
}

// validateCustomClaims validates custom claims before token operations.
// Uses deep validation for built-in Claims, standard Validate() plus
// registered claims string sanitization for other types.
func validateCustomClaims(claims CustomClaims) error {
	if err := requireNonNilClaims(claims); err != nil {
		return err
	}
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
	rc, err := requireRegisteredClaims(claims)
	if err != nil {
		return err
	}
	if err := validateRegisteredClaimsStrings(rc); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidClaims, err)
	}
	return nil
}

// requireRegisteredClaims returns the RegisteredClaims pointer from a custom
// claims implementation. A nil return — which would otherwise nil-panic at the
// next field access inside the Processor — is converted to a returned error,
// so a broken CustomClaims implementation surfaces as ErrInvalidClaims instead
// of a panic (SEC-003).
func requireRegisteredClaims(claims CustomClaims) (*RegisteredClaims, error) {
	rc := claims.GetRegisteredClaims()
	if rc == nil {
		return nil, fmt.Errorf("%w: GetRegisteredClaims returned nil", ErrInvalidClaims)
	}
	return rc, nil
}

// createTokenWithCustomClaims creates a signed token from custom claims.
// Caller must validate claims before calling this function.
func createTokenWithCustomClaims(p *Processor, claims CustomClaims, ttl time.Duration, tokenType string) (string, error) {
	rc, err := requireRegisteredClaims(claims)
	if err != nil {
		return "", err
	}

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

	// For *Claims, use pool copy to avoid mutating caller's struct.
	// Shallow struct copy is safe: we only modify scalar RegisteredClaims fields
	// (IssuedAt, ExpiresAt, Issuer, ID, TokenType). Slice/map headers are shared
	// with the caller's struct, but json.Encoder only reads them and the pool
	// Claims is reset before reuse.
	if c, ok := claims.(*Claims); ok {
		claimsCopy := getClaims()
		defer putClaims(claimsCopy)
		*claimsCopy = *c
		if err := p.setRegisteredDefaults(&claimsCopy.RegisteredClaims, ttl); err != nil {
			return "", err
		}
		claimsCopy.TokenType = tokenType
		return p.signClaims(claimsCopy)
	}

	// For other custom types, save and restore RegisteredClaims to avoid
	// mutating the caller's struct (consistent with built-in Claims behavior).
	orig := *rc
	defer func() { *rc = orig }()

	if err := p.setRegisteredDefaults(rc, ttl); err != nil {
		return "", err
	}
	rc.TokenType = tokenType
	return p.signClaims(claims)
}

// validateTokenIntoCustomClaims parses and validates a token into custom claims.
func validateTokenIntoCustomClaims(p *Processor, tokenString string, claims CustomClaims) error {
	token, err := p.parseToken(tokenString, claims)
	if err != nil {
		// %w twice: keep the underlying sentinel (e.g. ErrAlgorithmMismatch)
		// reachable via errors.Is, as on the Validate paths.
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	defer internal.ReleaseCore(token)

	if !token.Valid {
		return ErrInvalidToken
	}

	rc, err := requireRegisteredClaims(claims)
	if err != nil {
		return err
	}
	return p.validateRegistered(rc)
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
//
// It returns a descriptive error rather than the ErrInvalidClaims sentinel so
// that validateCustomClaims can wrap it once — otherwise the Create path
// produces a redundant "invalid claims: invalid claims" message. Callers that
// need the sentinel should use errors.Is on the error returned by Create,
// which wraps this with ErrInvalidClaims.
func (c *Claims) Validate() error {
	if c.UserID == "" && c.Username == "" {
		return errors.New("user_id or username is required")
	}
	return nil
}
