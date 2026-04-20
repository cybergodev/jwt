package jwt

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// 🧪 COMPREHENSIVE JWT TESTS: Core Functionality
// Consolidates: processor_test.go, convenience_test.go, config_test.go,
// blacklist_test.go, ratelimit_test.go, edge_cases_test.go, timezone_test.go

const testSecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

// newTestProcessor creates a Processor for testing with the given secret key.
func newTestProcessor(secretKey string) (*Processor, error) {
	cfg := DefaultConfig()
	cfg.SecretKey = secretKey
	return New(cfg)
}

// ============================================================================
// PROCESSOR TESTS
// ============================================================================

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
	processor, err := newTestProcessor(testSecretKey)
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
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}
	if token == "" || len(strings.Split(token, ".")) != 3 {
		t.Error("Invalid token format")
	}

	// Validate token
	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}
	if parsedClaims.UserID != claims.UserID {
		t.Errorf("UserID mismatch: got %s, want %s", parsedClaims.UserID, claims.UserID)
	}

	// Revoke token
	if err := processor.RevokeToken(token); err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Validate revoked token
	_, valid, err = processor.ValidateToken(token)
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

	claims := Claims{UserID: "user123", Username: "testuser"}

	// Create refresh token
	refreshToken, err := processor.CreateRefreshToken(claims)
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	// Validate refresh token
	parsedClaims, valid, err := processor.ValidateToken(refreshToken)
	if err != nil || !valid {
		t.Fatalf("Refresh token validation failed: %v", err)
	}
	if parsedClaims.UserID != claims.UserID {
		t.Error("Refresh token claims mismatch")
	}

	// Use refresh token to get new access token
	newToken, err := processor.RefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}
	if newToken == "" {
		t.Error("New token should not be empty")
	}

	// Validate new token
	_, valid, err = processor.ValidateToken(newToken)
	if err != nil || !valid {
		t.Error("New token should be valid")
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
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}
	if parsedClaims.Issuer != "test-service" {
		t.Errorf("Expected issuer 'test-service', got '%s'", parsedClaims.Issuer)
	}
}

func TestProcessorClose(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := processor.Close(); err != nil {
		t.Errorf("Failed to close processor: %v", err)
	}

	// Operations should fail after closing
	claims := Claims{UserID: "test"}
	if _, err := processor.CreateToken(claims); err == nil {
		t.Error("Expected error when creating token on closed processor")
	}

	// Double close should return error
	if err := processor.Close(); err == nil {
		t.Error("Expected error when closing already closed processor")
	}
}

func TestConcurrentOperations(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numGoroutines = 50
	const numOperations = 20

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				claims := Claims{
					UserID:   fmt.Sprintf("user%d-%d", id, j),
					Username: fmt.Sprintf("test%d-%d", id, j),
				}

				token, err := processor.CreateToken(claims)
				if err != nil {
					errors <- fmt.Errorf("create token error: %v", err)
					return
				}

				_, valid, err := processor.ValidateToken(token)
				if err != nil || !valid {
					errors <- fmt.Errorf("validate token error: %v", err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// Note: Config tests moved to config_test.go
// Note: Blacklist tests moved to blacklist_test.go
// Note: Rate limit tests moved to coverage_test.go

// ============================================================================
// EDGE CASES TESTS
// ============================================================================

func TestTokenExpiration(t *testing.T) {
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  1 * time.Second,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
		Blacklist:       DefaultBlacklistConfig(),
	}

	processor, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Token should be valid initially
	_, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		t.Fatal("Token should be valid initially")
	}

	// Wait for token to expire
	time.Sleep(1500 * time.Millisecond)

	// Token should be invalid after expiration
	_, valid, _ = processor.ValidateToken(token)
	if valid {
		t.Error("Token should be invalid after expiration")
	}
}

// Note: MalformedTokens test moved to security_test.go
// Note: SpecialCharactersInClaims test moved to coverage_test.go
// Note: LargeClaims test moved to coverage_test.go
// Note: NumericDateSerialization test moved to types_test.go
// Note: TokenWithTimestamps test moved to types_test.go
