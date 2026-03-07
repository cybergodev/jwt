package jwt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// CustomClaims defines the interface for custom claims types.
// Types implementing this interface can be used with generic token functions.
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

// CreateTokenWithClaims creates a token with custom claims type.
// The claims must implement the CustomClaims interface.
// This is the generic version of Processor.CreateToken for custom claim types.
//
// Example:
//
//	claims := &MyClaims{UserID: "123"}
//	token, err := jwt.CreateTokenWithClaims(processor, claims)
func CreateTokenWithClaims(p *Processor, claims CustomClaims) (string, error) {
	if p.closed.Load() {
		return "", ErrProcessorClosed
	}

	return createTokenWithCustomClaims(p, claims, p.accessTokenTTL)
}

// ValidateTokenWithClaims validates a token and populates the provided claims.
// The claims parameter must be a pointer to a type implementing CustomClaims.
// Returns the same claims pointer on success for convenience.
//
// Example:
//
//	claims := &MyClaims{}
//	result, valid, err := jwt.ValidateTokenWithClaims(processor, token, claims)
func ValidateTokenWithClaims(p *Processor, tokenString string, claims CustomClaims) (CustomClaims, bool, error) {
	if p.closed.Load() {
		return nil, false, ErrProcessorClosed
	}

	if tokenString == "" {
		return nil, false, ErrEmptyToken
	}

	valid, err := validateTokenIntoCustomClaims(p, tokenString, claims)
	if err != nil {
		return nil, false, err
	}

	if !valid {
		return nil, false, nil
	}

	// Check blacklist using the registered claims
	regClaims := claims.GetRegisteredClaims()
	if regClaims.ID != "" {
		isBlacklisted, err := p.blacklistManager.IsBlacklisted(regClaims.ID)
		if err != nil {
			return nil, false, err
		}
		if isBlacklisted {
			return nil, false, ErrTokenRevoked
		}
	}

	// Run custom validation
	if err := claims.Validate(); err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}

	return claims, true, nil
}

// CreateRefreshTokenWithClaims creates a refresh token with custom claims type.
func CreateRefreshTokenWithClaims(p *Processor, claims CustomClaims) (string, error) {
	if p.closed.Load() {
		return "", ErrProcessorClosed
	}

	return createTokenWithCustomClaims(p, claims, p.refreshTokenTTL)
}

// createTokenWithCustomClaims handles the actual token creation for custom claims.
func createTokenWithCustomClaims(p *Processor, claims CustomClaims, ttl time.Duration) (string, error) {
	regClaims := claims.GetRegisteredClaims()

	n := p.clock.Now()
	if regClaims.IssuedAt.IsZero() {
		regClaims.IssuedAt = NewNumericDate(n)
	}
	if regClaims.ExpiresAt.IsZero() {
		regClaims.ExpiresAt = NewNumericDate(n.Add(ttl))
	}
	if regClaims.Issuer == "" {
		regClaims.Issuer = p.issuer
	}
	if regClaims.ID == "" {
		tokenID, err := internal.GenerateTokenID()
		if err != nil {
			return "", fmt.Errorf("failed to generate token ID: %w", err)
		}
		regClaims.ID = tokenID
	}

	// Validate claims after setting standard fields
	if err := claims.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}

	signingMethod, err := internal.GetInternalSigningMethod(string(p.signingMethod))
	if err != nil {
		return "", err
	}

	token := internal.NewTokenWithClaims(signingMethod, claims)

	// Use appropriate key based on algorithm type
	if p.isAsymmetric {
		return token.SignedString(p.asymmetricKey)
	}
	return token.SignedString(p.secretKey)
}

// validateTokenIntoCustomClaims parses and validates a token into custom claims.
func validateTokenIntoCustomClaims(p *Processor, tokenString string, claims CustomClaims) (bool, error) {
	token, err := internal.ParseWithClaims(tokenString, claims, func(token *internal.Core) (any, error) {
		if alg, ok := token.Header["alg"].(string); !ok || alg != string(p.signingMethod) {
			return nil, ErrInvalidToken
		}
		// Use appropriate key based on algorithm type
		if p.isAsymmetric {
			return p.verificationKey, nil
		}
		return p.secretKey, nil
	})

	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return false, nil
	}

	// Validate standard claims
	regClaims := claims.GetRegisteredClaims()
	now := p.clock.Now()

	if !regClaims.ExpiresAt.IsZero() && now.After(regClaims.ExpiresAt.Time) {
		return false, nil
	}

	if !regClaims.NotBefore.IsZero() && now.Before(regClaims.NotBefore.Time) {
		return false, nil
	}

	if regClaims.Issuer != "" && regClaims.Issuer != p.issuer {
		return false, nil
	}

	return true, nil
}

// ParseUnverified parses a token without verifying the signature.
// This is useful for extracting claims from a token when you don't have the key.
// WARNING: The returned claims are NOT validated and should NOT be trusted.
func (p *Processor) ParseUnverified(tokenString string, claims any) error {
	if p.closed.Load() {
		return ErrProcessorClosed
	}

	if tokenString == "" {
		return ErrEmptyToken
	}

	_, _, err := internal.ParseUnverified(tokenString, claims)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	return nil
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

// MarshalJSON implements json.Marshaler for Claims to ensure proper serialization.
func (c *Claims) MarshalJSON() ([]byte, error) {
	type Alias Claims
	return json.Marshal((*Alias)(c))
}

// UnmarshalJSON implements json.Unmarshaler for Claims to ensure proper deserialization.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type Alias Claims
	return json.Unmarshal(data, (*Alias)(c))
}
