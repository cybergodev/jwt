package jwt

import (
	"testing"
	"time"
)

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

func TestNormalizeConfigRateLimit(t *testing.T) {
	t.Run("defaults when enabled", func(t *testing.T) {
		cfg := Config{SecretKey: testSecretKey, EnableRateLimit: true, RateLimitRate: 0, RateLimitWindow: 0}
		normalized := normalizeConfig(cfg)

		if normalized.RateLimitRate != 100 {
			t.Errorf("Expected default RateLimitRate=100, got %d", normalized.RateLimitRate)
		}
		if normalized.RateLimitWindow != time.Minute {
			t.Errorf("Expected default RateLimitWindow=1m, got %v", normalized.RateLimitWindow)
		}
	})

	t.Run("preserves custom values", func(t *testing.T) {
		cfg := Config{SecretKey: testSecretKey, EnableRateLimit: true, RateLimitRate: 50, RateLimitWindow: 30 * time.Second}
		normalized := normalizeConfig(cfg)

		if normalized.RateLimitRate != 50 {
			t.Errorf("Expected RateLimitRate=50, got %d", normalized.RateLimitRate)
		}
		if normalized.RateLimitWindow != 30*time.Second {
			t.Errorf("Expected RateLimitWindow=30s, got %v", normalized.RateLimitWindow)
		}
	})
}

func TestBlacklistConfigValidate(t *testing.T) {
	tests := []struct {
		name            string
		blacklistConfig BlacklistConfig
		wantError       bool
	}{
		{"zero max size (normalized)", BlacklistConfig{MaxSize: 0, CleanupInterval: time.Minute}, false},
		{"negative max size", BlacklistConfig{MaxSize: -1, CleanupInterval: time.Minute}, true},
		{"zero cleanup interval (normalized)", BlacklistConfig{MaxSize: 1000, CleanupInterval: 0}, false},
		{"negative cleanup interval", BlacklistConfig{MaxSize: 1000, CleanupInterval: -1 * time.Minute}, true},
		{"valid config", BlacklistConfig{MaxSize: 1000, CleanupInterval: time.Minute}, false},
		{"custom store bypasses validation", BlacklistConfig{Store: newTestMockStore()}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SecretKey = testSecretKey
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

func TestConfigValidateNil(t *testing.T) {
	var cfg *Config
	err := cfg.Validate()
	if err != ErrInvalidConfig {
		t.Errorf("Expected ErrInvalidConfig for nil config, got %v", err)
	}
}
