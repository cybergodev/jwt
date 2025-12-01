package jwt

import (
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal/security"
)

// Config represents JWT processor configuration
type Config struct {
	// SecretKey is the secret key used for signing tokens (minimum 32 bytes required)
	SecretKey string `yaml:"secret_key" json:"secret_key"`

	// AccessTokenTTL defines the lifetime of access tokens
	AccessTokenTTL time.Duration `yaml:"access_token_ttl" json:"access_token_ttl"`

	// RefreshTokenTTL defines the lifetime of refresh tokens (must be greater than AccessTokenTTL)
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" json:"refresh_token_ttl"`

	// Issuer identifies the principal that issued the JWT
	Issuer string `yaml:"issuer" json:"issuer"`

	// SigningMethod specifies the algorithm used to sign tokens
	SigningMethod SigningMethod `yaml:"signing_method" json:"signing_method"`

	// EnableRateLimit enables rate limiting for token creation
	EnableRateLimit bool `yaml:"enable_rate_limit" json:"enable_rate_limit"`

	// RateLimitRate specifies the maximum number of tokens per window
	RateLimitRate int `yaml:"rate_limit_rate" json:"rate_limit_rate"`

	// RateLimitWindow defines the time window for rate limiting
	RateLimitWindow time.Duration `yaml:"rate_limit_window" json:"rate_limit_window"`

	// RateLimiter allows providing a custom rate limiter instance
	RateLimiter *RateLimiter `yaml:"-" json:"-"`
}

// DefaultConfig returns a secure default configuration for production use
func DefaultConfig() Config {
	return Config{
		SecretKey:       "",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "jwt-service",
		SigningMethod:   SigningMethodHS256,
		EnableRateLimit: false,
		RateLimitRate:   100,
		RateLimitWindow: time.Minute,
		RateLimiter:     nil,
	}
}

// Validate validates the configuration and returns an error if invalid
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	keyLen := len(c.SecretKey)
	if keyLen < 32 {
		return fmt.Errorf("%w: minimum 32 bytes required, got %d", ErrInvalidSecretKey, keyLen)
	}

	if security.IsWeakKey([]byte(c.SecretKey)) {
		return fmt.Errorf("%w: key must have sufficient entropy and complexity", ErrInvalidSecretKey)
	}

	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("%w: TTL must be positive", ErrInvalidConfig)
	}

	if c.AccessTokenTTL >= c.RefreshTokenTTL {
		return fmt.Errorf("%w: access token TTL must be less than refresh token TTL", ErrInvalidConfig)
	}

	switch c.SigningMethod {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		return nil
	case "":
		return nil
	default:
		return ErrInvalidSigningMethod
	}
}
