package jwt

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// 🧪 COMPREHENSIVE UNIT TESTS: JWT Processor Core Functionality

const testSecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

func TestProcessorCreation(t *testing.T) {
	tests := []struct {
		name      string
		secretKey string
		wantError bool
	}{
		{
			name:      "Valid secret key",
			secretKey: testSecretKey,
			wantError: false,
		},
		{
			name:      "Short secret key",
			secretKey: "short",
			wantError: true,
		},
		{
			name:      "Empty secret key",
			secretKey: "",
			wantError: true,
		},
		{
			name:      "Weak secret key",
			secretKey: "passwordpasswordpasswordpassword",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, err := New(tt.secretKey)
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

func TestProcessorWithConfig(t *testing.T) {
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  30 * time.Minute,
		RefreshTokenTTL: 48 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS384,
	}

	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
	if err != nil {
		t.Fatalf("Failed to create processor with config: %v", err)
	}
	defer processor.Close()

	// Test that configuration is applied
	claims := Claims{
		UserID:   "test-user",
		Username: "testuser",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Error("Token should be valid")
	}

	if parsedClaims.Issuer != "test-service" {
		t.Errorf("Expected issuer 'test-service', got '%s'", parsedClaims.Issuer)
	}
}

func TestTokenCreation(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		claims    Claims
		wantError bool
	}{
		{
			name: "Valid claims",
			claims: Claims{
				UserID:   "user123",
				Username: "testuser",
				Role:     "admin",
			},
			wantError: false,
		},
		{
			name: "Minimal claims",
			claims: Claims{
				UserID: "user123",
			},
			wantError: false,
		},
		{
			name: "Claims with permissions",
			claims: Claims{
				UserID:      "user123",
				Username:    "testuser",
				Permissions: []string{"read", "write", "admin"},
			},
			wantError: false,
		},
		{
			name: "Claims with extra fields",
			claims: Claims{
				UserID:   "user123",
				Username: "testuser",
				Extra: map[string]any{
					"department": "engineering",
					"level":      5,
				},
			},
			wantError: false,
		},
		{
			name: "Empty claims",
			claims: Claims{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := processor.CreateToken(tt.claims)
			if tt.wantError {
				if err == nil {
					t.Error("Expected error for invalid claims")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if token == "" {
				t.Error("Expected non-empty token")
			}

			// Verify token format (should have 3 parts separated by dots)
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("Expected 3 token parts, got %d", len(parts))
			}
		})
	}
}

func TestTokenValidation(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create a valid token
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		wantValid bool
		wantError bool
	}{
		{
			name:      "Valid token",
			token:     token,
			wantValid: true,
			wantError: false,
		},
		{
			name:      "Empty token",
			token:     "",
			wantValid: false,
			wantError: true,
		},
		{
			name:      "Invalid format",
			token:     "invalid.token",
			wantValid: false,
			wantError: true,
		},
		{
			name:      "Tampered token",
			token:     token[:len(token)-10] + "tampered123",
			wantValid: false,
			wantError: false,
		},
		{
			name:      "Malformed token",
			token:     "not.a.valid.jwt.token",
			wantValid: false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedClaims, valid, err := processor.ValidateToken(tt.token)
			
			if tt.wantError {
				if err == nil {
					t.Error("Expected error")
				}
				return
			}

			if err != nil && !tt.wantError {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if valid != tt.wantValid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.wantValid, valid)
			}

			if tt.wantValid && parsedClaims != nil {
				if parsedClaims.UserID != claims.UserID {
					t.Errorf("Expected UserID=%s, got UserID=%s", claims.UserID, parsedClaims.UserID)
				}
				if parsedClaims.Username != claims.Username {
					t.Errorf("Expected Username=%s, got Username=%s", claims.Username, parsedClaims.Username)
				}
			}
		})
	}
}

func TestTokenRevocation(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Token should be valid initially
	_, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if !valid {
		t.Error("Token should be valid initially")
	}

	// Revoke the token
	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Token should be invalid after revocation
	_, valid, err = processor.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for revoked token")
	}
	if valid {
		t.Error("Token should be invalid after revocation")
	}
}

func TestProcessorClose(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Close the processor
	err = processor.Close()
	if err != nil {
		t.Errorf("Failed to close processor: %v", err)
	}

	// Operations should fail after closing
	claims := Claims{UserID: "test"}
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Expected error when creating token on closed processor")
	}

	_, _, err = processor.ValidateToken("test.token.here")
	if err == nil {
		t.Error("Expected error when validating token on closed processor")
	}
}

func TestContextCancellation(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	claims := Claims{UserID: "test", Username: "test"}
	_, err = processor.CreateTokenWithContext(ctx, claims)
	if err == nil {
		t.Error("Expected error due to cancelled context")
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"
	_, _, err = processor.ValidateTokenWithContext(ctx, token)
	if err == nil {
		t.Error("Expected error due to cancelled context")
	}
}

func TestConcurrentOperations(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numGoroutines = 100
	const numOperations = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	// Test concurrent token creation and validation
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
				if err != nil {
					errors <- fmt.Errorf("validate token error: %v", err)
					return
				}
				if !valid {
					errors <- fmt.Errorf("token should be valid")
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}
}
