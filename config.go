package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// Config is the unified configuration for JWT Processor.
// Use DefaultConfig() to get a configuration with sensible defaults.
type Config struct {
	// Signing configuration (choose one)
	SecretKey       string        // For HMAC algorithms (minimum 32 bytes)
	SigningKey      any           // For asymmetric algorithms (*rsa.PrivateKey or *ecdsa.PrivateKey)
	VerificationKey any           // Optional: public key for verification only (*rsa.PublicKey or *ecdsa.PublicKey)
	SigningMethod   SigningMethod // HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

	// Token configuration
	AccessTokenTTL    time.Duration `yaml:"access_token_ttl" json:"access_token_ttl"`
	RefreshTokenTTL   time.Duration `yaml:"refresh_token_ttl" json:"refresh_token_ttl"`
	Issuer            string        `yaml:"issuer" json:"issuer"`
	ExpectedAudience  string        `yaml:"expected_audience" json:"expected_audience"` // Optional: reject tokens without matching aud claim

	// Blacklist configuration (embedded)
	Blacklist BlacklistConfig `yaml:"blacklist" json:"blacklist"`

	// Rate limiting
	EnableRateLimit bool              `yaml:"enable_rate_limit" json:"enable_rate_limit"`
	RateLimitRate   int               `yaml:"rate_limit_rate" json:"rate_limit_rate"`
	RateLimitWindow time.Duration     `yaml:"rate_limit_window" json:"rate_limit_window"`
	RateLimiter     RateLimitProvider `yaml:"-" json:"-"`

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
		// bool zero-value is false — indistinguishable from "not set".
		// Always enable for built-in store to prevent unbounded growth.
		c.Blacklist.EnableAutoCleanup = true
	}

	return c
}

// Validate validates the configuration.
// Returns an error if the configuration is invalid.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
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

	if !c.SigningMethod.isValid() {
		return ErrInvalidSigningMethod
	}

	// Validate blacklist configuration
	if err := c.Blacklist.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	return nil
}

// validateSigningKey validates the signing key based on the signing method.
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
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: RSA method requires *rsa.PrivateKey, got %T", ErrInvalidSecretKey, key)
		}
		// Typed nil like (*rsa.PrivateKey)(nil) passes type assertion but is still nil
		if rsaKey == nil {
			return fmt.Errorf("%w: RSA key cannot be nil", ErrInvalidSecretKey)
		}
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: ECDSA method requires *ecdsa.PrivateKey, got %T", ErrInvalidSecretKey, key)
		}
		// Typed nil like (*ecdsa.PrivateKey)(nil) passes type assertion but is still nil
		if ecdsaKey == nil {
			return fmt.Errorf("%w: ECDSA key cannot be nil", ErrInvalidSecretKey)
		}
	}
	return nil
}

// isAsymmetric returns true if the signing method uses asymmetric keys.
func (c *Config) isAsymmetric() bool {
	return c.SigningMethod.isAsymmetric()
}

// validateVerificationKey validates the optional verification key for asymmetric methods.
// When nil, the SigningKey is used for both signing and verification.
func validateVerificationKey(method SigningMethod, key any) error {
	if key == nil {
		return nil
	}
	switch method {
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: VerificationKey must be *rsa.PublicKey for RSA, got %T", ErrInvalidSecretKey, key)
		}
		if rsaKey == nil {
			return fmt.Errorf("%w: RSA VerificationKey cannot be nil", ErrInvalidSecretKey)
		}
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: VerificationKey must be *ecdsa.PublicKey for ECDSA, got %T", ErrInvalidSecretKey, key)
		}
		if ecdsaKey == nil {
			return fmt.Errorf("%w: ECDSA VerificationKey cannot be nil", ErrInvalidSecretKey)
		}
	}
	return nil
}
