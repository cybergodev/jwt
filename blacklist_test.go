package jwt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// BLACKLIST TESTS - Tests for blacklist.go
// ============================================================================

// TestBlacklistOperationsBasic tests basic blacklist operations
func TestBlacklistOperationsBasic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
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

	// Revoke half of the tokens
	for i := 0; i < numTokens/2; i++ {
		if err := processor.RevokeToken(tokens[i]); err != nil {
			t.Fatalf("Failed to revoke token %d: %v", i, err)
		}
	}

	// Check token validity
	for i, token := range tokens {
		_, valid, err := processor.ValidateToken(token)

		if i < numTokens/2 {
			if err == nil || valid {
				t.Errorf("Token %d should be invalid after revocation", i)
			}
		} else {
			if err != nil || !valid {
				t.Errorf("Token %d should still be valid", i)
			}
		}
	}
}

// TestBlacklistCleanupMechanism tests blacklist cleanup mechanism
func TestBlacklistCleanupMechanism(t *testing.T) {
	blacklistConfig := BlacklistConfig{
		CleanupInterval:   100 * time.Millisecond,
		EnableAutoCleanup: true,
		MaxSize:           1000,
	}

	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = blacklistConfig
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if err := processor.RevokeToken(token); err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Cleanup mechanism should be running without errors
	t.Log("Cleanup test completed successfully")
}

// TestIsTokenRevokedFunction tests IsTokenRevoked function
func TestIsTokenRevokedFunction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Token should not be revoked initially
	revoked, err := processor.IsTokenRevoked(token)
	if err != nil {
		t.Fatalf("IsTokenRevoked failed: %v", err)
	}
	if revoked {
		t.Error("Token should not be revoked initially")
	}

	// Revoke the token
	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Token should now be revoked
	revoked, err = processor.IsTokenRevoked(token)
	if err != nil {
		t.Fatalf("IsTokenRevoked failed: %v", err)
	}
	if !revoked {
		t.Error("Token should be revoked after RevokeToken")
	}
}

// TestIsTokenRevokedNoBlacklist tests IsTokenRevoked when no blacklist configured
func TestIsTokenRevokedNoBlacklist(t *testing.T) {
	processor, err := newTestProcessor("Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024")
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Should return false when no blacklist is configured
	revoked, err := processor.IsTokenRevoked(token)
	if err != nil {
		t.Fatalf("IsTokenRevoked failed: %v", err)
	}
	if revoked {
		t.Error("Token should not be revoked when no blacklist is configured")
	}
}

// TestBlacklistConcurrentOps tests blacklist under high concurrency
func TestBlacklistConcurrentOps(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numTokens = 200

	// Create tokens
	tokens := make([]string, numTokens)
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

	var wg sync.WaitGroup

	// Concurrent revoke and validate
	wg.Add(numTokens * 2)

	for i := 0; i < numTokens; i++ {
		// Revoke goroutine
		go func(idx int) {
			defer wg.Done()
			processor.RevokeToken(tokens[idx])
		}(i)

		// Validate goroutine (may race with revoke)
		go func(idx int) {
			defer wg.Done()
			processor.ValidateToken(tokens[idx])
		}(i)
	}

	wg.Wait()
}

// TestBlacklistConfigDefaults tests BlacklistConfig defaults
func TestBlacklistConfigDefaults(t *testing.T) {
	cfg := DefaultBlacklistConfig()

	if cfg.CleanupInterval != 5*time.Minute {
		t.Errorf("Expected CleanupInterval=5m, got %v", cfg.CleanupInterval)
	}
	if cfg.MaxSize != 100000 {
		t.Errorf("Expected MaxSize=100000, got %d", cfg.MaxSize)
	}
	if !cfg.EnableAutoCleanup {
		t.Error("Expected EnableAutoCleanup=true")
	}
}

// TestBlacklistConfigCreateManager tests CreateManager with custom store
func TestBlacklistConfigCreateManager(t *testing.T) {
	cfg := BlacklistConfig{
		Store: &configTestMockStore{},
	}

	manager := cfg.CreateManager()
	if manager == nil {
		t.Error("CreateManager should return non-nil manager")
	}
}
