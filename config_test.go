package jwt

import (
	"testing"
	"time"
)

// ============================================================================
// CONFIG TESTS - Tests for config.go
// Migrated and consolidated from jwt_test.go and coverage_test.go
// ============================================================================

// TestConfigDefaultValues tests DefaultConfig returns expected defaults
func TestConfigDefaultValues(t *testing.T) {
	config := DefaultConfig()

	if config.SecretKey != "" {
		t.Error("Default config should not have a preset secret key")
	}
	if config.AccessTokenTTL != 15*time.Minute {
		t.Errorf("Expected AccessTokenTTL=15m, got %v", config.AccessTokenTTL)
	}
	if config.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("Expected RefreshTokenTTL=7d, got %v", config.RefreshTokenTTL)
	}
	if config.SigningMethod != SigningMethodHS256 {
		t.Errorf("Expected SigningMethod=HS256, got %s", config.SigningMethod)
	}
	if config.Issuer != "jwt-service" {
		t.Errorf("Expected Issuer=jwt-service, got %s", config.Issuer)
	}
	if config.RateLimitRate != 100 {
		t.Errorf("Expected RateLimitRate=100, got %d", config.RateLimitRate)
	}
	if config.RateLimitWindow != time.Minute {
		t.Errorf("Expected RateLimitWindow=1m, got %v", config.RateLimitWindow)
	}
}

// TestConfigValidateBasic tests basic config validation scenarios
func TestConfigValidateBasic(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
	}{
		{
			name: "Valid config",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
				Blacklist:       DefaultBlacklistConfig(),
			},
			wantError: false,
		},
		{
			name: "Short secret key",
			config: Config{
				SecretKey:       "short",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				SigningMethod:   SigningMethodHS256,
			},
			wantError: true,
		},
		{
			name: "Zero access token TTL",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  0,
				RefreshTokenTTL: 24 * time.Hour,
				SigningMethod:   SigningMethodHS256,
			},
			wantError: true,
		},
		{
			name: "Access TTL >= Refresh TTL",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  24 * time.Hour,
				RefreshTokenTTL: 12 * time.Hour,
				SigningMethod:   SigningMethodHS256,
			},
			wantError: true,
		},
		{
			name: "Invalid signing method",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				SigningMethod:   "INVALID",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError && err == nil {
				t.Error("Expected validation error")
			} else if !tt.wantError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

// Note: Additional edge case tests consolidated into coverage_test.go

// TestNormalizeConfigDefaults tests that normalizeConfig fills in default values
func TestNormalizeConfigDefaults(t *testing.T) {
	cfg := Config{SecretKey: testSecretKey}
	normalized := normalizeConfig(cfg)

	if normalized.AccessTokenTTL != 15*time.Minute {
		t.Errorf("Expected default AccessTokenTTL=15m, got %v", normalized.AccessTokenTTL)
	}
	if normalized.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("Expected default RefreshTokenTTL=7d, got %v", normalized.RefreshTokenTTL)
	}
	if normalized.Issuer != "jwt-service" {
		t.Errorf("Expected default Issuer=jwt-service, got %s", normalized.Issuer)
	}
	if normalized.SigningMethod != SigningMethodHS256 {
		t.Errorf("Expected default SigningMethod=HS256, got %s", normalized.SigningMethod)
	}
}

// TestNormalizeConfigPreservesCustom tests that normalizeConfig preserves custom values
func TestNormalizeConfigPreservesCustom(t *testing.T) {
	cfg := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  30 * time.Minute,
		RefreshTokenTTL: 14 * 24 * time.Hour,
		Issuer:          "custom-issuer",
		SigningMethod:   SigningMethodHS512,
	}
	normalized := normalizeConfig(cfg)

	if normalized.AccessTokenTTL != 30*time.Minute {
		t.Errorf("Expected custom AccessTokenTTL=30m, got %v", normalized.AccessTokenTTL)
	}
	if normalized.RefreshTokenTTL != 14*24*time.Hour {
		t.Errorf("Expected custom RefreshTokenTTL=14d, got %v", normalized.RefreshTokenTTL)
	}
	if normalized.Issuer != "custom-issuer" {
		t.Errorf("Expected custom Issuer=custom-issuer, got %s", normalized.Issuer)
	}
	if normalized.SigningMethod != SigningMethodHS512 {
		t.Errorf("Expected custom SigningMethod=HS512, got %s", normalized.SigningMethod)
	}
}

// TestNormalizeConfigRateLimitDefaults tests rate limit defaults when enabled
func TestNormalizeConfigRateLimitDefaults(t *testing.T) {
	cfg := Config{
		SecretKey:       testSecretKey,
		EnableRateLimit: true,
		RateLimitRate:   0,
		RateLimitWindow: 0,
	}
	normalized := normalizeConfig(cfg)

	if normalized.RateLimitRate != 100 {
		t.Errorf("Expected default RateLimitRate=100, got %d", normalized.RateLimitRate)
	}
	if normalized.RateLimitWindow != time.Minute {
		t.Errorf("Expected default RateLimitWindow=1m, got %v", normalized.RateLimitWindow)
	}
}

// TestNormalizeConfigRateLimitPreserved tests rate limit values preserved when set
func TestNormalizeConfigRateLimitPreserved(t *testing.T) {
	cfg := Config{
		SecretKey:       testSecretKey,
		EnableRateLimit: true,
		RateLimitRate:   50,
		RateLimitWindow: 30 * time.Second,
	}
	normalized := normalizeConfig(cfg)

	if normalized.RateLimitRate != 50 {
		t.Errorf("Expected RateLimitRate=50, got %d", normalized.RateLimitRate)
	}
	if normalized.RateLimitWindow != 30*time.Second {
		t.Errorf("Expected RateLimitWindow=30s, got %v", normalized.RateLimitWindow)
	}
}

// TestBlacklistConfigValidate tests BlacklistConfig validation
func TestBlacklistConfigValidate(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"

	tests := []struct {
		name            string
		blacklistConfig BlacklistConfig
		wantError       bool
	}{
		{
			name: "zero max size (normalized) (normalized)",
			blacklistConfig: BlacklistConfig{
				MaxSize:         0,
				CleanupInterval: time.Minute,
			},
			wantError: false,
		},
		{
			name: "negative max size",
			blacklistConfig: BlacklistConfig{
				MaxSize:         -1,
				CleanupInterval: time.Minute,
			},
			wantError: true,
		},
		{
			name: "zero cleanup interval (normalized)",
			blacklistConfig: BlacklistConfig{
				MaxSize:         1000,
				CleanupInterval: 0,
			},
			wantError: false,
		},
		{
			name: "negative cleanup interval",
			blacklistConfig: BlacklistConfig{
				MaxSize:         1000,
				CleanupInterval: -1 * time.Minute,
			},
			wantError: true,
		},
		{
			name: "valid config",
			blacklistConfig: BlacklistConfig{
				MaxSize:         1000,
				CleanupInterval: time.Minute,
			},
			wantError: false,
		},
		{
			name: "custom store bypasses validation",
			blacklistConfig: BlacklistConfig{
				Store: &configTestMockStore{},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SecretKey = secretKey
			cfg.Blacklist = tt.blacklistConfig
			_, err := New(cfg)
			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestConfigValidateNil tests nil config validation
func TestConfigValidateNil(t *testing.T) {
	var cfg *Config
	err := cfg.Validate()
	if err != ErrInvalidConfig {
		t.Errorf("Expected ErrInvalidConfig for nil config, got %v", err)
	}
}

// configTestMockStore is a mock implementation for config testing
type configTestMockStore struct{}

func (m *configTestMockStore) Add(tokenID string, expiresAt time.Time) error {
	return nil
}

func (m *configTestMockStore) Contains(tokenID string) (bool, error) {
	return false, nil
}

func (m *configTestMockStore) Close() error {
	return nil
}
