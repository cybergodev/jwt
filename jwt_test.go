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

func TestTokenLifecycle(t *testing.T) {
	processor, err := New(testSecretKey)
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
	processor, err := New(testSecretKey)
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
	processor, err := New(testSecretKey)
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
	processor, err := New(testSecretKey)
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

// ============================================================================
// CONVENIENCE API TESTS
// ============================================================================

func TestConvenienceFunctions(t *testing.T) {
	cache.mu.Lock()
	cache.entries = make(map[string]*cacheEntry, 16)
	cache.mu.Unlock()

	claims := Claims{UserID: "user123", Username: "testuser", Role: "admin"}

	token, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := ValidateToken(testSecretKey, token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}
	if parsedClaims.UserID != claims.UserID {
		t.Errorf("UserID mismatch: got %s, want %s", parsedClaims.UserID, claims.UserID)
	}

	if err := RevokeToken(testSecretKey, token); err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	_, valid, err = ValidateToken(testSecretKey, token)
	if err == nil || valid {
		t.Error("Revoked token should be invalid")
	}
}

func TestProcessorCaching(t *testing.T) {
	cache.mu.Lock()
	cache.entries = make(map[string]*cacheEntry, 16)
	cache.mu.Unlock()

	claims := Claims{UserID: "user123", Username: "testuser"}

	_, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token1: %v", err)
	}

	_, err = CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token2: %v", err)
	}

	cache.mu.Lock()
	cacheSize := len(cache.entries)
	cache.mu.Unlock()

	if cacheSize != 1 {
		t.Errorf("Expected 1 cached processor, got %d", cacheSize)
	}
}

func TestProcessorCacheLimit(t *testing.T) {
	cache.mu.Lock()
	cache.entries = make(map[string]*cacheEntry, 16)
	cache.mu.Unlock()

	claims := Claims{UserID: "user123", Username: "testuser"}

	const maxCacheSize = 100
	for i := 0; i < maxCacheSize+10; i++ {
		uniquePart := fmt.Sprintf("Unique%dWithRandomData%x", i, i*31337+54321)
		secretKey := "StrongBaseFor" + uniquePart + "MoreRandomStuff"

		_, err := CreateToken(secretKey, claims)
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}
	}

	cache.mu.Lock()
	cacheSize := len(cache.entries)
	cache.mu.Unlock()

	if cacheSize > maxCacheSize {
		t.Errorf("Cache size exceeded limit: expected <= %d, got %d", maxCacheSize, cacheSize)
	}
}

// ============================================================================
// CONFIG TESTS
// ============================================================================

func TestDefaultConfig(t *testing.T) {
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

func TestWeakSecretKeyDetection(t *testing.T) {
	weakKeys := []string{
		"password",
		"12345678901234567890123456789012",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"qwertyuiopasdfghjklzxcvbnm123456",
	}

	for _, weakKey := range weakKeys {
		config := Config{
			SecretKey:       weakKey,
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
			SigningMethod:   SigningMethodHS256,
		}

		if err := config.Validate(); err == nil {
			t.Errorf("Should reject weak key: %s", weakKey)
		}
	}
}

// ============================================================================
// BLACKLIST TESTS
// ============================================================================

func TestBlacklistOperations(t *testing.T) {
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

func TestBlacklistCleanup(t *testing.T) {
	blacklistConfig := BlacklistConfig{
		CleanupInterval:   100 * time.Millisecond,
		EnableAutoCleanup: true,
		MaxSize:           1000,
	}

	processor, err := NewWithBlacklist(testSecretKey, blacklistConfig)
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

// ============================================================================
// RATE LIMIT TESTS
// ============================================================================

func TestConvenienceMethodsNoRateLimit(t *testing.T) {
	claims := Claims{UserID: "test-user", Username: "testuser"}

	// Test that we can create many tokens quickly without rate limiting
	for i := 0; i < 100; i++ {
		token, err := CreateToken(testSecretKey, claims)
		if err != nil {
			t.Fatalf("CreateToken failed on iteration %d: %v", i, err)
		}

		_, valid, err := ValidateToken(testSecretKey, token)
		if err != nil || !valid {
			t.Fatalf("ValidateToken failed on iteration %d: %v", i, err)
		}
	}
}

func TestProcessorWithRateLimit(t *testing.T) {
	config := DefaultConfig()
	config.EnableRateLimit = true
	config.RateLimitRate = 5
	config.RateLimitWindow = time.Minute

	processor, err := New(testSecretKey, config)
	if err != nil {
		t.Fatalf("Failed to create processor with rate limit: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "test-user", Username: "testuser"}

	// Create tokens until we hit the rate limit
	successCount := 0
	rateLimitHit := false

	for i := 0; i < 10; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			if err == ErrRateLimitExceeded {
				rateLimitHit = true
				break
			}
			t.Fatalf("Unexpected error on iteration %d: %v", i, err)
		}
		successCount++
	}

	if !rateLimitHit {
		t.Fatalf("Expected to hit rate limit, but created %d tokens successfully", successCount)
	}
	if successCount == 0 {
		t.Fatal("Expected to create at least some tokens before hitting rate limit")
	}
}

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
	}

	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
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
	_, valid, err = processor.ValidateToken(token)
	if valid {
		t.Error("Token should be invalid after expiration")
	}
}

func TestMalformedTokens(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	malformedTokens := []string{
		"",
		"invalid",
		"invalid.token",
		"invalid.token.signature.extra",
		".token.signature",
		"header.token.",
		strings.Repeat("a", 10000),
	}

	for _, malformedToken := range malformedTokens {
		_, valid, _ := processor.ValidateToken(malformedToken)
		if valid {
			t.Errorf("Malformed token should not be valid: %s", malformedToken)
		}
	}
}

func TestSpecialCharactersInClaims(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	specialClaims := []Claims{
		{UserID: "user@example.com", Username: "test user"},
		{UserID: "user123", Username: "测试用户"}, // Unicode
		{UserID: "user123", Username: "user'with'apostrophes"},
	}

	for i, claims := range specialClaims {
		token, err := processor.CreateToken(claims)
		if err != nil {
			t.Fatalf("Test %d: Failed to create token with special characters: %v", i, err)
		}

		parsedClaims, valid, err := processor.ValidateToken(token)
		if err != nil || !valid {
			t.Fatalf("Test %d: Failed to validate token with special characters: %v", i, err)
		}
		if parsedClaims.Username != claims.Username {
			t.Errorf("Test %d: Username mismatch", i)
		}
	}
}

func TestLargeClaims(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test with too many permissions
	permissions := make([]string, 200)
	for i := range permissions {
		permissions[i] = fmt.Sprintf("perm%d", i)
	}

	claims := Claims{
		UserID:      "test",
		Username:    "test",
		Permissions: permissions,
	}

	if _, err := processor.CreateToken(claims); err == nil {
		t.Error("Should reject claims with too many permissions")
	}

	// Test with too many extra fields
	extra := make(map[string]any)
	for i := 0; i < 100; i++ {
		extra[fmt.Sprintf("field%d", i)] = "value"
	}

	claims = Claims{
		UserID:   "test",
		Username: "test",
		Extra:    extra,
	}

	if _, err := processor.CreateToken(claims); err == nil {
		t.Error("Should reject claims with too many extra fields")
	}
}

func TestNumericDateSerialization(t *testing.T) {
	now := time.Now()
	nd := NewNumericDate(now)

	if nd.Time.IsZero() {
		t.Error("NewNumericDate should not create zero time")
	}
	if nd.Unix() != now.Unix() {
		t.Errorf("Unix timestamp mismatch: got %d, expected %d", nd.Unix(), now.Unix())
	}
}

func TestTokenWithTimestamps(t *testing.T) {
	claims := Claims{UserID: "test_user", Username: "test"}

	token, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := ValidateToken(testSecretKey, token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}

	// Verify timestamps are set
	if parsedClaims.IssuedAt.IsZero() {
		t.Error("IssuedAt should be set automatically")
	}
	if parsedClaims.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set automatically")
	}
}
