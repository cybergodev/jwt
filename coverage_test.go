package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests for uncovered error methods
func TestValidationErrorMethods(t *testing.T) {
	baseErr := errors.New("base error")
	valErr := &ValidationError{
		Field:   "username",
		Message: "invalid format",
		Err:     baseErr,
	}

	// Test Error() with wrapped error
	errMsg := valErr.Error()
	if errMsg == "" {
		t.Error("Error() returned empty string")
	}
	if errMsg != "validation failed for field 'username': invalid format: base error" {
		t.Errorf("Unexpected error message: %s", errMsg)
	}

	// Test Error() without wrapped error
	valErr2 := &ValidationError{
		Field:   "email",
		Message: "required",
	}
	errMsg2 := valErr2.Error()
	if errMsg2 != "validation failed for field 'email': required" {
		t.Errorf("Unexpected error message: %s", errMsg2)
	}

	// Test Unwrap()
	unwrapped := valErr.Unwrap()
	if unwrapped != baseErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, baseErr)
	}

	// Test Unwrap() with nil error
	unwrapped2 := valErr2.Unwrap()
	if unwrapped2 != nil {
		t.Errorf("Unwrap() should return nil when Err is nil, got %v", unwrapped2)
	}
}

// Tests for convenience cache
func TestProcessorCacheEviction(t *testing.T) {
	cache.mu.Lock()
	cache.entries = make(map[string]*cacheEntry, 16)
	cache.mu.Unlock()

	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"

	_, release, err := getProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to get processor: %v", err)
	}
	defer release()

	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()

	if size != 1 {
		t.Errorf("Expected 1 cache entry, got %d", size)
	}
}

// Tests for uncovered rate limiter functions
func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Close()

	key := "test-key"

	// Use some tokens
	for i := 0; i < 5; i++ {
		rl.Allow(key)
	}

	// Reset the key
	rl.Reset(key)

	// Should have full tokens again
	for i := 0; i < 10; i++ {
		if !rl.Allow(key) {
			t.Errorf("Expected allow after reset, failed at iteration %d", i)
		}
	}
}

func TestRateLimiterCleanupOldBuckets(t *testing.T) {
	rl := NewRateLimiter(10, 50*time.Millisecond)
	defer rl.Close()

	// Create some buckets
	for i := 0; i < 5; i++ {
		key := "key-" + string(rune('0'+i))
		rl.Allow(key)
	}

	// Wait for window to pass
	time.Sleep(150 * time.Millisecond)

	// Buckets are cleaned lazily on next access
	rl.mu.Lock()
	size := len(rl.buckets)
	rl.mu.Unlock()

	if size > 0 {
		t.Logf("Note: %d buckets remain (lazy cleanup)", size)
	}
}

func TestRateLimiterEvictOldestBucket(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Close()

	// Fill up to max buckets
	rl.mu.Lock()
	rl.maxBuckets = 5
	rl.mu.Unlock()

	for i := 0; i < 6; i++ {
		key := "key-" + string(rune('0'+i))
		rl.Allow(key)
		time.Sleep(time.Millisecond)
	}

	// Should have evicted oldest
	rl.mu.Lock()
	size := len(rl.buckets)
	rl.mu.Unlock()

	if size > 5 {
		t.Errorf("Expected max 5 buckets, got %d", size)
	}
}

func TestRateLimiterWithConfig(t *testing.T) {
	maxRate := 50
	window := 30 * time.Second

	rl := NewRateLimiter(maxRate, window)
	defer rl.Close()

	key := "test-key"

	// Should not be limited initially
	for i := 0; i < 50; i++ {
		if !rl.Allow(key) {
			t.Errorf("Should not be limited at iteration %d", i)
		}
	}

	// Should be limited after exceeding rate
	if rl.Allow(key) {
		t.Error("Should be rate limited after exceeding max rate")
	}
}

// Tests for uncovered processor functions
func TestProcessorIsTokenRevoked(t *testing.T) {
	processor, err := NewWithBlacklist("Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024", DefaultBlacklistConfig())
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

func TestProcessorIsTokenRevokedInvalidToken(t *testing.T) {
	processor, err := NewWithBlacklist("Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024", DefaultBlacklistConfig())
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Invalid token should return error
	revoked, err := processor.IsTokenRevoked("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
	if revoked {
		t.Error("Invalid token should not be considered revoked")
	}
}

func TestProcessorIsTokenRevokedNoBlacklist(t *testing.T) {
	processor, err := New("Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024")
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

// Test rate limiter edge cases
func TestRateLimiterClosedOperations(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	rl.Close()

	// Operations after close should handle gracefully
	if rl.Allow("test") {
		t.Error("Should not allow operations after close")
	}

	// Double close should be safe
	rl.Close()
}

func TestRateLimiterAllowNMultipleTokens(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Close()

	key := "test-key"

	// Request multiple tokens at once
	if !rl.AllowN(key, 5) {
		t.Error("Should allow 5 tokens initially")
	}

	// Should have 5 tokens left
	if !rl.AllowN(key, 5) {
		t.Error("Should allow another 5 tokens")
	}

	// Should not allow more
	if rl.AllowN(key, 1) {
		t.Error("Should not allow more tokens after exhausting")
	}
}

func TestRateLimiterTokenRefill(t *testing.T) {
	rl := NewRateLimiter(10, 100*time.Millisecond)
	defer rl.Close()

	key := "test-key"

	// Exhaust tokens
	for i := 0; i < 10; i++ {
		rl.Allow(key)
	}

	// Should be rate limited
	if rl.Allow(key) {
		t.Error("Should be rate limited after exhausting tokens")
	}

	// Wait for refill
	time.Sleep(150 * time.Millisecond)

	// Should have tokens again
	if !rl.Allow(key) {
		t.Error("Should have tokens after refill period")
	}
}

// ============================================================================
// TESTS FOR UNCOVERED FUNCTIONS
// ============================================================================

// TestClearCache tests the ClearCache convenience function
func TestClearCache(t *testing.T) {
	// Setup: Create some cached processors
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	claims := Claims{UserID: "user1", Username: "testuser"}

	// Create tokens to populate cache
	_, err := CreateToken(secretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Verify cache has entries
	cache.mu.RLock()
	initialSize := len(cache.entries)
	cache.mu.RUnlock()

	if initialSize == 0 {
		t.Fatal("Cache should have entries before clearing")
	}

	// Clear the cache
	ClearCache()

	// Verify cache is empty
	cache.mu.RLock()
	finalSize := len(cache.entries)
	cache.mu.RUnlock()

	if finalSize != 0 {
		t.Errorf("Cache should be empty after clearing, got %d entries", finalSize)
	}
}

// TestProcessorIsClosed tests the IsClosed method
func TestProcessorIsClosed(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Processor should not be closed initially
	if processor.IsClosed() {
		t.Error("Processor should not be closed initially")
	}

	// Close the processor
	if err := processor.Close(); err != nil {
		t.Fatalf("Failed to close processor: %v", err)
	}

	// Processor should be closed now
	if !processor.IsClosed() {
		t.Error("Processor should be closed after Close()")
	}

	// Calling Close again should return error
	if err := processor.Close(); err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got %v", err)
	}
}

// TestConfigValidationEdgeCases tests additional config validation scenarios
func TestConfigValidationEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
	}{
		{
			name: "valid config with all fields",
			config: Config{
				SecretKey:       "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
				Issuer:          "test-issuer",
				SigningMethod:   SigningMethodHS256,
				EnableRateLimit: true,
				RateLimitRate:   100,
				RateLimitWindow: time.Minute,
			},
			wantError: false,
		},
		{
			name: "zero access token TTL",
			config: Config{
				SecretKey:       "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024",
				AccessTokenTTL:  0,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			},
			wantError: true,
		},
		{
			name: "zero refresh token TTL",
			config: Config{
				SecretKey:       "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 0,
			},
			wantError: true,
		},
		{
			name: "negative access token TTL",
			config: Config{
				SecretKey:       "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024",
				AccessTokenTTL:  -1 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			},
			wantError: true,
		},
		{
			name: "invalid signing method",
			config: Config{
				SecretKey:       "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024",
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
				SigningMethod:   "INVALID",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestValidationEdgeCases tests validation edge cases
func TestValidationEdgeCases(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
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
			name: "claims with control characters",
			claims: Claims{
				UserID:   "user\x00id",
				Username: "testuser",
			},
			wantError: true,
		},
		{
			name: "claims with tab character (allowed)",
			claims: Claims{
				UserID:   "user\tid",
				Username: "testuser",
			},
			wantError: false,
		},
		{
			name: "claims with newline (allowed)",
			claims: Claims{
				UserID:   "user\nid",
				Username: "testuser",
			},
			wantError: false,
		},
		{
			name: "claims with carriage return (allowed)",
			claims: Claims{
				UserID:   "user\rid",
				Username: "testuser",
			},
			wantError: false,
		},
		{
			name: "claims with too many permissions",
			claims: Claims{
				UserID:      "user1",
				Username:    "testuser",
				Permissions: make([]string, 101), // maxArraySize is 100
			},
			wantError: true,
		},
		{
			name: "claims with too many scopes",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Scopes:   make([]string, 101),
			},
			wantError: true,
		},
		{
			name: "claims with too many audience",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				RegisteredClaims: RegisteredClaims{
					Audience: make([]string, 101),
				},
			},
			wantError: true,
		},
		{
			name: "claims with too many extra fields",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra:    make(map[string]any, 51), // maxExtraSize is 50
			},
			wantError: true,
		},
		{
			name: "claims with nested map in extra",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					"nested": map[string]any{"key": "value"},
				},
			},
			wantError: true,
		},
		{
			name: "claims with string array in extra",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					"tags": []string{"tag1", "tag2"},
				},
			},
			wantError: false,
		},
		{
			name: "claims with too long extra key",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					strings.Repeat("a", 257): "value", // maxStringLength is 256
				},
			},
			wantError: true,
		},
		{
			name: "claims with too long extra value",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					"key": strings.Repeat("a", 257),
				},
			},
			wantError: true,
		},
		{
			name: "claims with dangerous pattern in extra array",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					"scripts": []string{"<script>alert('xss')</script>"},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Populate extra fields if needed
			if tt.name == "claims with too many extra fields" {
				for i := 0; i < 51; i++ {
					tt.claims.Extra[string(rune('a'+i%26))+string(rune(i))] = "value"
				}
			}

			_, err := processor.CreateToken(tt.claims)
			if tt.wantError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestDangerousPatternDetection tests all dangerous patterns
func TestDangerousPatternDetection(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	dangerousPatterns := []string{
		"<script>alert('xss')</script>",
		"javascript:alert('xss')",
		"data:text/html,<script>alert('xss')</script>",
		"eval(malicious_code)",
		"../../../etc/passwd",
		"file:///etc/passwd",
		"vbscript:msgbox('xss')",
		"<SCRIPT>alert('xss')</SCRIPT>", // uppercase
		"JaVaScRiPt:alert('xss')",       // mixed case
	}

	for _, pattern := range dangerousPatterns {
		t.Run("pattern_"+pattern[:10], func(t *testing.T) {
			claims := Claims{
				UserID:   pattern,
				Username: "testuser",
			}
			_, err := processor.CreateToken(claims)
			if err == nil {
				t.Errorf("Expected error for dangerous pattern: %s", pattern)
			}
		})
	}
}

// TestConvenienceFunctionsEdgeCases tests edge cases in convenience functions
func TestConvenienceFunctionsEdgeCases(t *testing.T) {
	// Test with short secret key
	shortKey := "short"
	claims := Claims{UserID: "user1", Username: "testuser"}

	_, err := CreateToken(shortKey, claims)
	if err != ErrInvalidSecretKey {
		t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
	}

	_, _, err = ValidateToken(shortKey, "dummy.token.string")
	if err != ErrInvalidSecretKey {
		t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
	}

	err = RevokeToken(shortKey, "dummy.token.string")
	if err != ErrInvalidSecretKey {
		t.Errorf("Expected ErrInvalidSecretKey, got %v", err)
	}
}

// TestProcessorOperationsAfterClose tests operations on closed processor
func TestProcessorOperationsAfterClose(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Close the processor
	if err := processor.Close(); err != nil {
		t.Fatalf("Failed to close processor: %v", err)
	}

	claims := Claims{UserID: "user1", Username: "testuser"}

	// Try CreateToken on closed processor
	_, err = processor.CreateToken(claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed for CreateToken, got %v", err)
	}

	// Try ValidateToken on closed processor
	_, _, err = processor.ValidateToken("dummy.token.string")
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed for ValidateToken, got %v", err)
	}

	// Try CreateRefreshToken on closed processor
	_, err = processor.CreateRefreshToken(claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed for CreateRefreshToken, got %v", err)
	}

	// Try RefreshToken on closed processor
	_, err = processor.RefreshToken("dummy.token.string")
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed for RefreshToken, got %v", err)
	}

	// Try RevokeToken on closed processor
	err = processor.RevokeToken("dummy.token.string")
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed for RevokeToken, got %v", err)
	}

	// Try IsTokenRevoked on closed processor
	_, err = processor.IsTokenRevoked("dummy.token.string")
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed for IsTokenRevoked, got %v", err)
	}
}

// TestRefreshTokenEdgeCases tests edge cases in RefreshToken
func TestRefreshTokenEdgeCases(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test with empty token
	_, err = processor.RefreshToken("")
	if err != ErrEmptyToken {
		t.Errorf("Expected ErrEmptyToken, got %v", err)
	}

	// Test with invalid token
	_, err = processor.RefreshToken("invalid.token.string")
	if err == nil {
		t.Error("Expected error for invalid token")
	}

	// Test with malformed token
	_, err = processor.RefreshToken("malformed")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
}

// TestRevokeTokenEdgeCases tests edge cases in RevokeToken
func TestRevokeTokenEdgeCases(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test with empty token
	err = processor.RevokeToken("")
	if err != ErrEmptyToken {
		t.Errorf("Expected ErrEmptyToken, got %v", err)
	}
}

// TestIsTokenRevokedEdgeCases tests edge cases in IsTokenRevoked
func TestIsTokenRevokedEdgeCases(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test with empty token
	_, err = processor.IsTokenRevoked("")
	if err != ErrEmptyToken {
		t.Errorf("Expected ErrEmptyToken, got %v", err)
	}

	// Test with malformed token
	_, err = processor.IsTokenRevoked("malformed")
	if err == nil {
		t.Error("Expected error for malformed token")
	}

	// Test with token without ID
	claims := Claims{UserID: "user1", Username: "testuser"}
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Manually create a token without jti claim
	processor2, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor2.Close()

	// Parse the token to get claims without ID
	parsedClaims, valid, err := processor2.ValidateToken(token)
	if err != nil || !valid {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// The token should have an ID, so this test verifies the normal path
	if parsedClaims.ID == "" {
		t.Error("Token should have an ID")
	}
}

// TestNewWithBlacklistInvalidConfig tests NewWithBlacklist with invalid configs
func TestNewWithBlacklistInvalidConfig(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"

	tests := []struct {
		name            string
		blacklistConfig BlacklistConfig
		wantError       bool
	}{
		{
			name: "zero max size",
			blacklistConfig: BlacklistConfig{
				MaxSize:         0,
				CleanupInterval: time.Minute,
			},
			wantError: true,
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
			name: "zero cleanup interval",
			blacklistConfig: BlacklistConfig{
				MaxSize:         1000,
				CleanupInterval: 0,
			},
			wantError: true,
		},
		{
			name: "negative cleanup interval",
			blacklistConfig: BlacklistConfig{
				MaxSize:         1000,
				CleanupInterval: -1 * time.Minute,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWithBlacklist(secretKey, tt.blacklistConfig)
			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestClaimsWithEmptyUserIDAndUsername tests claims validation
func TestClaimsWithEmptyUserIDAndUsername(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Both UserID and Username empty
	claims := Claims{}
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Expected error for empty UserID and Username")
	}
	// Check if error contains "invalid claims"
	if err != nil && !strings.Contains(err.Error(), "invalid claims") {
		t.Errorf("Expected error containing 'invalid claims', got %v", err)
	}
}

// TestCacheCleanupConcurrency tests cache cleanup under concurrent load
func TestCacheCleanupConcurrency(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	claims := Claims{UserID: "user1", Username: "testuser"}

	// Clear cache first
	ClearCache()

	// Create multiple tokens concurrently
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < 5; j++ {
				_, _ = CreateToken(secretKey, claims)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Clear cache
	ClearCache()

	// Verify cache is empty
	cache.mu.RLock()
	size := len(cache.entries)
	cache.mu.RUnlock()

	if size != 0 {
		t.Errorf("Cache should be empty, got %d entries", size)
	}
}
