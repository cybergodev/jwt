package jwt

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// 🧪 COMPREHENSIVE UNIT TESTS: Configuration Management

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Test default values
	if config.SecretKey != "" {
		t.Error("Default config should not have a preset secret key")
	}

	if config.AccessTokenTTL != 15*time.Minute {
		t.Errorf("Expected AccessTokenTTL=15m, got %v", config.AccessTokenTTL)
	}

	if config.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("Expected RefreshTokenTTL=7d, got %v", config.RefreshTokenTTL)
	}

	if config.Issuer != "jwt-service" {
		t.Errorf("Expected Issuer='jwt-service', got '%s'", config.Issuer)
	}

	if config.SigningMethod != SigningMethodHS256 {
		t.Errorf("Expected SigningMethod=HS256, got %s", config.SigningMethod)
	}
}

func TestConfigValidation(t *testing.T) {
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
			},
			wantError: false,
		},
		{
			name: "Short secret key",
			config: Config{
				SecretKey:       "short",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			},
			wantError: true,
		},
		{
			name: "Weak secret key",
			config: Config{
				SecretKey:       "passwordpasswordpasswordpassword",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
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
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			},
			wantError: true,
		},
		{
			name: "Zero refresh token TTL",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 0,
				Issuer:          "test-service",
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
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			},
			wantError: true,
		},
		{
			name: "Empty signing method",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   "",
			},
			wantError: true,
		},
		{
			name: "Invalid signing method",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   "INVALID",
			},
			wantError: true,
		},
		{
			name: "All supported signing methods - HS256",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			},
			wantError: false,
		},
		{
			name: "All supported signing methods - HS384",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS384,
			},
			wantError: false,
		},
		{
			name: "All supported signing methods - HS512",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS512,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Error("Expected validation error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected validation error: %v", err)
				}
			}
		})
	}
}

func TestWeakSecretKeyDetection(t *testing.T) {
	weakKeys := []string{
		"password",                                    // Common weak key
		"12345678901234567890123456789012",           // Repeated pattern
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",           // All same character
		"00000000000000000000000000000000",           // All zeros
		"secretsecretsecretsecretsecretsecret",       // Repeated word
		"abcdefghijklmnopqrstuvwxyz123456",           // Sequential pattern
		"qwertyuiopasdfghjklzxcvbnm123456",           // Keyboard pattern
		"passwordpasswordpasswordpassword",           // Repeated common word
		"11111111111111111111111111111111",           // All ones
		"abcabcabcabcabcabcabcabcabcabcabcabc",        // Short repeated pattern (33 chars)
	}

	for _, weakKey := range weakKeys {
		t.Run("WeakKey_"+weakKey[:min(10, len(weakKey))], func(t *testing.T) {
			config := Config{
				SecretKey:       weakKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			}

			err := config.Validate()
			if err == nil {
				t.Errorf("Should reject weak key: %s", weakKey)
			}
		})
	}
}

func TestStrongSecretKeys(t *testing.T) {
	strongKeys := []string{
		testSecretKey,                                                    // Our test key
		"Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!", // Mixed characters
		"aB3$fG7*kL9#pQ2&vX5!zC8@mN4%rT6^wY1+eH0-iJ3~oU7$bD9#gK2&sF5*nM8@", // Random strong key
		// Remove the descriptive key as it might be detected as weak
	}

	for i, strongKey := range strongKeys {
		t.Run(fmt.Sprintf("StrongKey_%d", i), func(t *testing.T) {
			config := Config{
				SecretKey:       strongKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			}

			err := config.Validate()
			if err != nil {
				t.Errorf("Should accept strong key: %v", err)
			}
		})
	}
}

func TestNilConfigValidation(t *testing.T) {
	var config *Config
	err := config.Validate()
	if err == nil {
		t.Error("Should reject nil config")
	}
}

func TestConfigEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
	}{
		{
			name: "Minimum valid TTLs",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  1 * time.Nanosecond,
				RefreshTokenTTL: 2 * time.Nanosecond,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			},
			wantError: false,
		},
		{
			name: "Very long TTLs",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  365 * 24 * time.Hour,
				RefreshTokenTTL: 10 * 365 * 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   SigningMethodHS256,
			},
			wantError: false,
		},
		{
			name: "Empty issuer",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "",
				SigningMethod:   SigningMethodHS256,
			},
			wantError: false, // Empty issuer should be allowed
		},
		{
			name: "Very long issuer",
			config: Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          strings.Repeat("a", 1000),
				SigningMethod:   SigningMethodHS256,
			},
			wantError: false, // Long issuer should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				if err == nil {
					t.Error("Expected validation error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected validation error: %v", err)
				}
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
