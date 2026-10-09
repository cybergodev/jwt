package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// Rate limiting sanity bounds. RateLimiter.AllowN additionally guards its
// refill arithmetic against overflow, so exceeding these bounds is a
// fail-fast UX concern rather than a safety one (direct NewRateLimiter users
// are covered by the AllowN guard alone).
const (
	maxRateLimitRate   = 1_000_000
	maxRateLimitWindow = 30 * 24 * time.Hour
)

// Config is the unified configuration for JWT Processor.
// Use DefaultConfig() to get a configuration with sensible defaults.
//
// The optional interface fields (Clock, RateLimiter, Blacklist.Store) must not
// be set to typed-nil pointers (e.g. (*FixedClock)(nil)): the interface value
// compares non-nil, so configuration passes and the first method call panics
// inside the nil implementation — user-supplied code, outside this library's
// panic-protection contract. Use an untyped nil to leave a field unset.
type Config struct {
	// Signing configuration (choose one). Fields not applicable to the chosen
	// SigningMethod are silently ignored: SecretKey applies only to HMAC
	// methods, SigningKey/VerificationKey only to asymmetric methods.
	SecretKey       string        // For HMAC algorithms (minimum 32 bytes)
	SigningKey      any           // For asymmetric algorithms (*rsa.PrivateKey or *ecdsa.PrivateKey)
	VerificationKey any           // Optional: public key for verification only (*rsa.PublicKey or *ecdsa.PublicKey)
	SigningMethod   SigningMethod // HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512

	// Token configuration
	// AccessTokenTTL is the lifetime of access tokens issued by Create.
	AccessTokenTTL time.Duration `yaml:"access_token_ttl" json:"access_token_ttl"`
	// RefreshTokenTTL is the lifetime of refresh tokens issued by CreateRefresh.
	// Must be greater than AccessTokenTTL.
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" json:"refresh_token_ttl"`
	// Issuer is written to the token's iss claim and checked during validation.
	// An empty value is replaced by the default ("jwt-service") before
	// validation, so issuer checking cannot be disabled through Config.
	Issuer string `yaml:"issuer" json:"issuer"`
	// ExpectedAudience, when non-empty, rejects tokens whose aud claim does not
	// contain this value during validation.
	ExpectedAudience string `yaml:"expected_audience" json:"expected_audience"`
	// RequireExpiration, when true, rejects tokens that lack an exp claim during
	// validation (Validate/ValidateInto/Refresh/RefreshInto) with ErrExpirationRequired.
	// Tokens issued by this processor always carry exp (derived from the TTL), so
	// this primarily governs tokens from other issuers or tokens missing exp —
	// without it, such a token never expires (RFC 7519 makes exp optional).
	// Default: false (historical behavior).
	RequireExpiration bool `yaml:"require_expiration" json:"require_expiration"`
	// RejectRefreshAsAccess, when true, makes Validate and ValidateInto reject
	// tokens whose token_type is "refresh", mirroring Refresh's rejection of
	// access tokens. Without it, a long-lived refresh token (RefreshTokenTTL,
	// default 7d) passes Validate for its full lifetime and can serve as an
	// access credential. Refresh and RefreshInto are never affected.
	// Default: false (historical behavior).
	RejectRefreshAsAccess bool `yaml:"reject_refresh_as_access" json:"reject_refresh_as_access"`
	// RotateRefreshTokens, when true, gives refresh tokens one-time-use
	// semantics: Refresh and RefreshInto revoke the supplied refresh token
	// (by its jti) before minting the new access token, so an accepted
	// refresh token cannot be replayed after the fact.
	//
	// Revocation runs before minting (fail-closed): if minting subsequently
	// fails — e.g. the rate limit trips — the old token is already revoked
	// and the subject must re-authenticate. A refresh token without a jti
	// cannot be revoked and is rejected with ErrTokenMissingID.
	//
	// Concurrency: rotation narrows but does not eliminate the replay window
	// across racing requests — two concurrent Refresh calls can both pass
	// validation before either revocation lands. A strict single-use
	// guarantee requires an atomic check-and-add in a custom BlacklistStore.
	//
	// Default: false (historical behavior: the old refresh token remains
	// valid until it expires or is explicitly revoked).
	RotateRefreshTokens bool `yaml:"rotate_refresh_tokens" json:"rotate_refresh_tokens"`
	// ClockSkew is the leeway applied to exp and nbf during validation, to
	// tolerate clock drift between the token issuer and this validator. A token
	// is accepted up to ClockSkew after its exp, and from ClockSkew before its
	// nbf. Zero (the default) applies no leeway and reproduces the historical
	// strict timing checks; negative values are rejected by Validate.
	ClockSkew time.Duration `yaml:"clock_skew" json:"clock_skew"`

	// Blacklist configuration (embedded)
	Blacklist BlacklistConfig `yaml:"blacklist" json:"blacklist"`

	// Rate limiting
	// EnableRateLimit enables per-subject rate limiting on token creation.
	// When false (the default), RateLimitRate and RateLimitWindow are ignored.
	// Note: an explicitly provided RateLimiter always takes effect regardless
	// of this flag — supplying one is treated as explicit intent.
	EnableRateLimit bool `yaml:"enable_rate_limit" json:"enable_rate_limit"`
	// RateLimitRate is the maximum number of tokens allowed per subject per window.
	RateLimitRate int `yaml:"rate_limit_rate" json:"rate_limit_rate"`
	// RateLimitWindow is the duration over which RateLimitRate is measured.
	RateLimitWindow time.Duration `yaml:"rate_limit_window" json:"rate_limit_window"`
	// RateLimiter optionally supplies a custom rate limiter. When nil and
	// EnableRateLimit is true, a built-in limiter is built from the fields above.
	// Ownership note: Processor.Close closes this limiter; do not share one
	// limiter instance across processors that may outlive each other — after
	// one processor closes it, Allow returns false and the others' token
	// creation fails with ErrRateLimitExceeded.
	RateLimiter RateLimitProvider `yaml:"-" json:"-"`

	// Clock provider for time operations (optional, defaults to SystemClock)
	Clock ClockProvider `yaml:"-" json:"-"`
}

// DefaultConfig returns a Config with sensible defaults.
// The caller must set SecretKey (for HMAC) or SigningKey (for asymmetric) before use.
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "jwt-service",
		SigningMethod:   SigningMethodHS256,
		Blacklist:       DefaultBlacklistConfig(),
		RateLimitRate:   100,
		RateLimitWindow: time.Minute,
	}
}

// normalizeConfig fills in default values for zero fields.
// This allows users to provide minimal configuration while still getting sensible defaults.
func normalizeConfig(c Config) Config {
	defaults := DefaultConfig()

	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = defaults.AccessTokenTTL
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = defaults.RefreshTokenTTL
	}
	if c.Issuer == "" {
		c.Issuer = defaults.Issuer
	}
	if c.SigningMethod == "" {
		c.SigningMethod = defaults.SigningMethod
	}
	if c.RateLimitRate == 0 && c.EnableRateLimit {
		c.RateLimitRate = defaults.RateLimitRate
	}
	if c.RateLimitWindow == 0 && c.EnableRateLimit {
		c.RateLimitWindow = defaults.RateLimitWindow
	}
	// Blacklist: apply per-field defaults when using built-in store
	if c.Blacklist.Store == nil {
		if c.Blacklist.MaxSize == 0 {
			c.Blacklist.MaxSize = defaults.Blacklist.MaxSize
		}
		if c.Blacklist.CleanupInterval == 0 {
			c.Blacklist.CleanupInterval = defaults.Blacklist.CleanupInterval
		}
		// For the built-in store, auto-cleanup is always enabled to prevent
		// unbounded memory growth. EnableAutoCleanup only takes effect with
		// a custom BlacklistStore.
		c.Blacklist.EnableAutoCleanup = true
	}

	return c
}

// Validate validates the configuration.
// Returns an error if the configuration is invalid.
//
// Note: New fills in defaults for zero-valued optional fields before
// validating, so a Config that fails when Validate is called directly may
// still be accepted by New. Start from DefaultConfig to match New's behavior.
//
// Returns errors:
//   - [ErrInvalidConfig]: nil config, invalid TTL values, or invalid blacklist config
//   - [ErrInvalidSecretKey]: missing key, key too short, weak key, wrong key type, or ECDSA curve mismatch
//   - [ErrInvalidSigningMethod]: unrecognized signing method
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	// Reject an unrecognized signing method before anything else:
	// validateSigningKey's branches match neither family for an unknown
	// method and would silently pass, letting downstream errors (TTL,
	// blacklist, ...) mask the actual problem.
	if !c.SigningMethod.isValid() {
		return ErrInvalidSigningMethod
	}

	// Validate signing key based on method type
	if err := c.validateSigningKey(); err != nil {
		return err
	}

	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("%w: TTL must be positive", ErrInvalidConfig)
	}

	if c.AccessTokenTTL >= c.RefreshTokenTTL {
		return fmt.Errorf("%w: access token TTL must be less than refresh token TTL", ErrInvalidConfig)
	}

	if c.ClockSkew < 0 {
		return fmt.Errorf("%w: clock skew must not be negative", ErrInvalidConfig)
	}

	// Rate limiting: reject absurd parameters up front. AllowN additionally
	// guards its refill arithmetic against overflow, so these bounds exist to
	// fail fast on misconfiguration rather than to guarantee the math.
	if c.EnableRateLimit {
		if c.RateLimitRate < 0 || c.RateLimitWindow < 0 {
			return fmt.Errorf("%w: rate limit parameters must not be negative", ErrInvalidConfig)
		}
		if c.RateLimitRate > maxRateLimitRate {
			return fmt.Errorf("%w: RateLimitRate must not exceed %d", ErrInvalidConfig, maxRateLimitRate)
		}
		if c.RateLimitWindow > maxRateLimitWindow {
			return fmt.Errorf("%w: RateLimitWindow must not exceed %s", ErrInvalidConfig, maxRateLimitWindow)
		}
	}

	// Validate blacklist configuration
	if err := c.Blacklist.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return nil
}

// validateSigningKey validates the signing key based on the signing method.
// Precondition: Validate has already confirmed the method is recognized, so
// exactly one of the two branches below matches.
func (c *Config) validateSigningKey() error {
	switch {
	case c.SigningMethod.isHMAC():
		// HMAC requires SecretKey
		keyLen := len(c.SecretKey)
		if keyLen < 32 {
			return fmt.Errorf("%w: minimum 32 bytes required, got %d", ErrInvalidSecretKey, keyLen)
		}
		if internal.IsWeakKey([]byte(c.SecretKey)) {
			return fmt.Errorf("%w: key must have sufficient entropy and complexity", ErrInvalidSecretKey)
		}
	case c.SigningMethod.isAsymmetric():
		// Asymmetric methods use shared validation
		if err := validateAsymmetricSigningKey(c.SigningMethod, c.SigningKey); err != nil {
			return err
		}
		if err := validateVerificationKey(c.SigningMethod, c.VerificationKey); err != nil {
			return err
		}
	}
	return nil
}

// validateAsymmetricSigningKey validates asymmetric signing keys (RSA/ECDSA).
// This is shared between Config and AsymmetricConfig validation.
func validateAsymmetricSigningKey(method SigningMethod, key any) error {
	if key == nil {
		return fmt.Errorf("%w: SigningKey is required for %s method", ErrInvalidSecretKey, method)
	}
	switch method {
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512,
		SigningMethodPS256, SigningMethodPS384, SigningMethodPS512:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: RSA method requires *rsa.PrivateKey, got %T", ErrInvalidSecretKey, key)
		}
		if rsaKey == nil {
			return fmt.Errorf("%w: RSA key cannot be nil", ErrInvalidSecretKey)
		}
		if rsaKey.N == nil {
			// A type-correct but empty key (nil modulus) would panic in BitLen().
			return fmt.Errorf("%w: RSA key has nil modulus", ErrInvalidSecretKey)
		}
		if rsaKey.N.BitLen() < 2048 {
			return fmt.Errorf("%w: RSA key must be at least 2048 bits, got %d", ErrInvalidSecretKey, rsaKey.N.BitLen())
		}
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: ECDSA method requires *ecdsa.PrivateKey, got %T", ErrInvalidSecretKey, key)
		}
		if ecdsaKey == nil {
			return fmt.Errorf("%w: ECDSA key cannot be nil", ErrInvalidSecretKey)
		}
		if err := validateECDSACurve(method, ecdsaKey.Curve); err != nil {
			return err
		}
	}
	return nil
}

// validateECDSACurve checks that the key's curve matches the expected curve for the signing method.
func validateECDSACurve(method SigningMethod, curve elliptic.Curve) error {
	if curve == nil {
		// A type-correct but empty key (nil curve) would panic in Params().
		return fmt.Errorf("%w: ECDSA curve cannot be nil", ErrInvalidSecretKey)
	}
	var expected elliptic.Curve
	switch method {
	case SigningMethodES256:
		expected = elliptic.P256()
	case SigningMethodES384:
		expected = elliptic.P384()
	case SigningMethodES512:
		expected = elliptic.P521()
	default:
		return nil
	}
	if curve != expected {
		return fmt.Errorf("%w: %s requires %s curve, got %s",
			ErrInvalidSecretKey, method, expected.Params().Name, curve.Params().Name)
	}
	return nil
}

// validateVerificationKey validates the optional verification key for asymmetric methods.
// When nil, the SigningKey is used for both signing and verification.
func validateVerificationKey(method SigningMethod, key any) error {
	if key == nil {
		return nil
	}
	switch method {
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512,
		SigningMethodPS256, SigningMethodPS384, SigningMethodPS512:
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: VerificationKey must be *rsa.PublicKey for RSA, got %T", ErrInvalidSecretKey, key)
		}
		if rsaKey == nil {
			return fmt.Errorf("%w: RSA VerificationKey cannot be nil", ErrInvalidSecretKey)
		}
		if rsaKey.N == nil {
			return fmt.Errorf("%w: RSA VerificationKey has nil modulus", ErrInvalidSecretKey)
		}
		if rsaKey.N.BitLen() < 2048 {
			return fmt.Errorf("%w: RSA VerificationKey must be at least 2048 bits, got %d", ErrInvalidSecretKey, rsaKey.N.BitLen())
		}
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: VerificationKey must be *ecdsa.PublicKey for ECDSA, got %T", ErrInvalidSecretKey, key)
		}
		if ecdsaKey == nil {
			return fmt.Errorf("%w: ECDSA VerificationKey cannot be nil", ErrInvalidSecretKey)
		}
		if ecdsaKey.Curve == nil {
			return fmt.Errorf("%w: ECDSA VerificationKey has nil curve", ErrInvalidSecretKey)
		}
	}
	return nil
}
