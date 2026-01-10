package jwt

import (
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal"
)

type Config struct {
	SecretKey        string        `yaml:"secret_key" json:"secret_key"`
	AccessTokenTTL   time.Duration `yaml:"access_token_ttl" json:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `yaml:"refresh_token_ttl" json:"refresh_token_ttl"`
	Issuer           string        `yaml:"issuer" json:"issuer"`
	SigningMethod    SigningMethod `yaml:"signing_method" json:"signing_method"`
	EnableRateLimit  bool          `yaml:"enable_rate_limit" json:"enable_rate_limit"`
	RateLimitRate    int           `yaml:"rate_limit_rate" json:"rate_limit_rate"`
	RateLimitWindow  time.Duration `yaml:"rate_limit_window" json:"rate_limit_window"`
	RateLimiter      *RateLimiter  `yaml:"-" json:"-"`
}

func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "jwt-service",
		SigningMethod:   SigningMethodHS256,
		RateLimitRate:   100,
		RateLimitWindow: time.Minute,
	}
}

func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	keyLen := len(c.SecretKey)
	if keyLen < 32 {
		return fmt.Errorf("%w: minimum 32 bytes required, got %d", ErrInvalidSecretKey, keyLen)
	}

	if internal.IsWeakKey([]byte(c.SecretKey)) {
		return fmt.Errorf("%w: key must have sufficient entropy and complexity", ErrInvalidSecretKey)
	}

	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("%w: TTL must be positive", ErrInvalidConfig)
	}

	if c.AccessTokenTTL >= c.RefreshTokenTTL {
		return fmt.Errorf("%w: access token TTL must be less than refresh token TTL", ErrInvalidConfig)
	}

	switch c.SigningMethod {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512, "":
	default:
		return ErrInvalidSigningMethod
	}

	return nil
}
