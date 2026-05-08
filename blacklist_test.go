package jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestBlacklistOperationsBasic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	const numTokens = 10
	tokens := make([]string, numTokens)

	for i := 0; i < numTokens; i++ {
		claims := Claims{UserID: fmt.Sprintf("user%d", i), Username: fmt.Sprintf("testuser%d", i)}
		token, err := processor.Create(&claims)
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}
		tokens[i] = token
	}

	// Revoke half of the tokens
	for i := 0; i < numTokens/2; i++ {
		if err := processor.Revoke(tokens[i]); err != nil {
			t.Fatalf("Failed to revoke token %d: %v", i, err)
		}
	}

	// Check token validity
	for i, token := range tokens {
		_, valid, err := processor.Validate(token)
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
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if err := processor.Revoke(token); err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Wait for cleanup to run at least once
	time.Sleep(200 * time.Millisecond)

	// Token should still be revoked after cleanup (cleanup removes expired entries, not active ones)
	_, valid, err := processor.Validate(token)
	if valid {
		t.Error("Token should remain revoked after cleanup cycle")
	}
	if err != ErrTokenRevoked {
		t.Errorf("Expected ErrTokenRevoked, got: %v", err)
	}
}

func TestIsRevokedFunction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Token should not be revoked initially
	revoked, err := processor.IsRevoked(token)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if revoked {
		t.Error("Token should not be revoked initially")
	}

	// Revoke the token
	if err := processor.Revoke(token); err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Token should now be revoked
	revoked, err = processor.IsRevoked(token)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !revoked {
		t.Error("Token should be revoked after Revoke")
	}
}

func TestIsRevokedNoBlacklist(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := Claims{UserID: "user123", Username: "testuser"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Should return false when no blacklist is configured
	revoked, err := processor.IsRevoked(token)
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if revoked {
		t.Error("Token should not be revoked when no blacklist is configured")
	}
}

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

func TestBlacklistConfigCreateManager(t *testing.T) {
	tests := []struct {
		name string
		cfg  BlacklistConfig
	}{
		{"custom store", BlacklistConfig{Store: newTestMockStore()}},
		{"default store", DefaultBlacklistConfig()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := tt.cfg.createManager()
			if manager == nil {
				t.Error("createManager should return non-nil manager")
			}
			_ = manager.Close() // test cleanup
		})
	}
}

func TestBlacklistDuplicateRevoke(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := Claims{UserID: "dup-user", Username: "testuser"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if err := processor.Revoke(token); err != nil {
		t.Fatalf("First revoke failed: %v", err)
	}

	// Second revoke of same token should succeed (idempotent)
	if err := processor.Revoke(token); err != nil {
		t.Errorf("Second revoke should succeed (idempotent), got: %v", err)
	}

	_, valid, _ := processor.Validate(token)
	if valid {
		t.Error("Token should remain revoked after duplicate revoke")
	}
}
