package jwt

import (
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal/security"
)

// Config represents JWT configuration
type Config struct {
	SecretKey       string         `yaml:"secret_key" json:"secret_key"`
	AccessTokenTTL  time.Duration  `yaml:"access_token_ttl" json:"access_token_ttl"`
	RefreshTokenTTL time.Duration  `yaml:"refresh_token_ttl" json:"refresh_token_ttl"`
	Issuer          string         `yaml:"issuer" json:"issuer"`
	SigningMethod   SigningMethod  `yaml:"signing_method" json:"signing_method"`
	Timezone        *time.Location   `yaml:"-" json:"-"`
	EnableRateLimit bool             `yaml:"enable_rate_limit" json:"enable_rate_limit"`
	RateLimit       *RateLimitConfig `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

// DefaultConfig returns a secure default configuration for production use
func DefaultConfig() Config {
	return Config{
		SecretKey:       "",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "jwt-service",
		SigningMethod:   SigningMethodHS256,
		Timezone:        time.Local,
		EnableRateLimit: false,
		RateLimit:       nil,
	}
}

// Validate validates the configuration and returns an error if invalid
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	if len(c.SecretKey) < 32 {
		return fmt.Errorf("secret key too short: minimum 32 bytes required, got %d", len(c.SecretKey))
	}

	if security.IsWeakKey([]byte(c.SecretKey)) {
		return fmt.Errorf("weak secret key detected: key must have sufficient entropy and complexity")
	}

	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("TTL must be positive")
	}

	if c.AccessTokenTTL >= c.RefreshTokenTTL {
		return fmt.Errorf("access token TTL must be less than refresh token TTL")
	}

	if c.SigningMethod == "" {
		return ErrInvalidSigningMethod
	}

	supportedMethods := map[SigningMethod]bool{
		SigningMethodHS256: true,
		SigningMethodHS384: true,
		SigningMethodHS512: true,
	}

	if !supportedMethods[c.SigningMethod] {
		return ErrInvalidSigningMethod
	}

	return nil
}
