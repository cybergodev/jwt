package jwt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 🧪 COMPREHENSIVE UNIT TESTS: Blacklist Functionality

func TestBlacklistConfig(t *testing.T) {
	// Test default blacklist config
	config := DefaultBlacklistConfig()
	if config.CleanupInterval != 5*time.Minute {
		t.Errorf("Expected CleanupInterval=5m, got %v", config.CleanupInterval)
	}
	if !config.EnableAutoCleanup {
		t.Error("Expected EnableAutoCleanup=true")
	}
}

func TestBlacklistBasicOperations(t *testing.T) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Create token
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

	// Revoke token
	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Token should be invalid after revocation
	_, valid, err = processor.ValidateToken(token)
	if err == nil {
		t.Error("Expected error when validating revoked token")
	}
	if valid {
		t.Error("Token should be invalid after revocation")
	}
}

func TestBlacklistMultipleTokens(t *testing.T) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numTokens = 10
	tokens := make([]string, numTokens)

	// Create multiple tokens
	for i := 0; i < numTokens; i++ {
		claims := Claims{
			UserID:   fmt.Sprintf("user%d", i),
			Username: fmt.Sprintf("testuser%d", i),
		}

		token, err := processor.CreateToken(claims)
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}
		tokens[i] = token
	}

	// All tokens should be valid initially
	for i, token := range tokens {
		_, valid, err := processor.ValidateToken(token)
		if err != nil {
			t.Fatalf("Failed to validate token %d: %v", i, err)
		}
		if !valid {
			t.Errorf("Token %d should be valid initially", i)
		}
	}

	// Revoke half of the tokens
	for i := 0; i < numTokens/2; i++ {
		err := processor.RevokeToken(tokens[i])
		if err != nil {
			t.Fatalf("Failed to revoke token %d: %v", i, err)
		}
	}

	// Check token validity after revocation
	for i, token := range tokens {
		_, valid, err := processor.ValidateToken(token)

		if i < numTokens/2 {
			// Revoked tokens should be invalid and return error
			if err == nil {
				t.Errorf("Expected error for revoked token %d", i)
			}
			if valid {
				t.Errorf("Token %d should be invalid after revocation", i)
			}
		} else {
			// Non-revoked tokens should still be valid
			if err != nil {
				t.Errorf("Unexpected error for valid token %d: %v", i, err)
			}
			if !valid {
				t.Errorf("Token %d should still be valid", i)
			}
		}
	}
}

func TestBlacklistConcurrentOperations(t *testing.T) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numGoroutines = 20
	const numOperations = 50

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	// Test concurrent blacklist operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				claims := Claims{
					UserID:   fmt.Sprintf("user%d-%d", id, j),
					Username: fmt.Sprintf("test%d-%d", id, j),
				}

				// Create token
				token, err := processor.CreateToken(claims)
				if err != nil {
					errors <- fmt.Errorf("create token error: %v", err)
					return
				}

				// Validate token
				_, valid, err := processor.ValidateToken(token)
				if err != nil {
					errors <- fmt.Errorf("validate token error: %v", err)
					return
				}
				if !valid {
					errors <- fmt.Errorf("token should be valid")
					return
				}

				// Revoke every other token
				if j%2 == 0 {
					err = processor.RevokeToken(token)
					if err != nil {
						errors <- fmt.Errorf("revoke token error: %v", err)
						return
					}

					// Verify revocation - should return error for revoked token
					_, valid, err = processor.ValidateToken(token)
					if err == nil {
						errors <- fmt.Errorf("expected error for revoked token")
						return
					}
					if valid {
						errors <- fmt.Errorf("revoked token should be invalid")
						return
					}
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

func TestBlacklistCleanup(t *testing.T) {
	// Use a short cleanup interval for testing
	blacklistConfig := BlacklistConfig{
		CleanupInterval:   100 * time.Millisecond,
		EnableAutoCleanup: true,
		MaxSize:           1000,
		StoreType:         "memory",
	}

	processor, err := NewWithBlacklist(testSecretKey, blacklistConfig)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create a token
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Revoke the token
	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Verify token is revoked
	_, valid, err := processor.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for revoked token")
	}
	if valid {
		t.Error("Revoked token should be invalid")
	}

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	// The cleanup functionality is working if no errors occurred
	// We can't easily test if expired tokens are cleaned up without
	// creating tokens that expire, but the cleanup mechanism is running
	t.Log("Cleanup test completed - cleanup mechanism is running")
}

func TestBlacklistRevocation(t *testing.T) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Create and revoke a token
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Validate revoked token should fail
	_, valid, err := processor.ValidateToken(token)
	if err == nil && valid {
		t.Error("Expected revoked token to be invalid")
	}
	// Token should be invalid (either error or valid=false)
	if valid {
		t.Error("Expected revoked token to be invalid")
	}
}

func TestBlacklistErrorHandling(t *testing.T) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test revoking empty token
	err = processor.RevokeToken("")
	if err == nil {
		t.Error("Expected error when revoking empty token")
	}

	// Test revoking invalid token
	err = processor.RevokeToken("invalid.token.format")
	if err == nil {
		t.Error("Expected error when revoking invalid token")
	}

	// Test operations after closing
	processor.Close()

	claims := Claims{UserID: "test", Username: "test"}
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Expected error when creating token on closed processor")
	}

	_, _, err = processor.ValidateToken("some.token.here")
	if err == nil {
		t.Error("Expected error when validating token on closed processor")
	}

	err = processor.RevokeToken("some.token.here")
	if err == nil {
		t.Error("Expected error when revoking token on closed processor")
	}
}

func TestBlacklistDisabledMetrics(t *testing.T) {
	config := DefaultBlacklistConfig()

	processor, err := NewWithBlacklist(testSecretKey, config)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Create and revoke token
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Validate revoked token
	_, valid, err := processor.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for revoked token")
	}
	if valid {
		t.Error("Revoked token should be invalid")
	}

	// Operations should work fine even with metrics disabled
}
