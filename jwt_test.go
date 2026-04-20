package jwt

import (
	"strings"
	"testing"
	"time"
)

const testSecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

func newTestProcessor(secretKey string) (*Processor, error) {
	cfg := DefaultConfig()
	cfg.SecretKey = secretKey
	return New(cfg)
}

func TestProcessorCreation(t *testing.T) {
	tests := []struct {
		name      string
		secretKey string
		wantError bool
	}{
		{"Valid secret key", testSecretKey, false},
		{"Short secret key", "short", true},
		{"Empty secret key", "", true},
		{"Weak secret key", "passwordpasswordpasswordpassword", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, err := newTestProcessor(tt.secretKey)
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error for secret key: %s", tt.secretKey)
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if processor == nil {
				t.Error("Expected processor to be created")
				return
			}
			defer processor.Close()
		})
	}
}

func TestTokenLifecycle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:      "user123",
		Username:    "testuser",
		Role:        "admin",
		Permissions: []string{"read", "write"},
		Extra:       map[string]any{"department": "engineering"},
	}

	// Create token
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}
	if token == "" || len(strings.Split(token, ".")) != 3 {
		t.Error("Invalid token format")
	}

	// Validate token
	parsedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}
	if parsedClaims.UserID != claims.UserID {
		t.Errorf("UserID mismatch: got %s, want %s", parsedClaims.UserID, claims.UserID)
	}
	if parsedClaims.Role != claims.Role {
		t.Errorf("Role mismatch: got %s, want %s", parsedClaims.Role, claims.Role)
	}

	// Revoke token
	if err := processor.Revoke(token); err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Validate revoked token
	_, valid, err = processor.Validate(token)
	if err == nil || valid {
		t.Error("Revoked token should be invalid")
	}
}

func TestRefreshToken(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "user123", Username: "testuser", Role: "admin"}

	// Create refresh token
	refreshToken, err := processor.CreateRefresh(&claims)
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	// Validate refresh token
	parsedClaims, valid, err := processor.Validate(refreshToken)
	if err != nil || !valid {
		t.Fatalf("Refresh token validation failed: %v", err)
	}
	if parsedClaims.UserID != claims.UserID {
		t.Error("Refresh token claims mismatch")
	}

	// Use refresh token to get new access token
	newToken, err := processor.Refresh(refreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}
	if newToken == "" {
		t.Error("New token should not be empty")
	}

	// Validate new access token and verify claims are preserved
	newClaims, valid, err := processor.Validate(newToken)
	if err != nil || !valid {
		t.Fatalf("New token should be valid: %v", err)
	}
	if newClaims.UserID != claims.UserID {
		t.Errorf("New token UserID mismatch: got %s, want %s", newClaims.UserID, claims.UserID)
	}
	if newClaims.Role != claims.Role {
		t.Errorf("New token Role mismatch: got %s, want %s", newClaims.Role, claims.Role)
	}
}

func TestProcessorWithConfig(t *testing.T) {
	config := DefaultConfig()
	config.SecretKey = testSecretKey
	config.AccessTokenTTL = 30 * time.Minute
	config.RefreshTokenTTL = 48 * time.Hour
	config.Issuer = "test-service"
	config.SigningMethod = SigningMethodHS384

	processor, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create processor with config: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "test-user", Username: "testuser"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}
	if parsedClaims.Issuer != "test-service" {
		t.Errorf("Expected issuer 'test-service', got '%s'", parsedClaims.Issuer)
	}
}

func TestTokenExpiration(t *testing.T) {
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  1 * time.Second,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	processor, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Token should be valid initially
	_, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatal("Token should be valid initially")
	}

	// Wait for token to expire
	time.Sleep(1100 * time.Millisecond)

	// Token should be invalid after expiration
	_, valid, _ = processor.Validate(token)
	if valid {
		t.Error("Token should be invalid after expiration")
	}
}
