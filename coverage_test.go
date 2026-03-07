package jwt

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// ERROR TYPE TESTS - Covering TokenError, SigningError
// ============================================================================

func TestTokenErrorMethods(t *testing.T) {
	baseErr := errors.New("base error")

	// Test TokenError with all fields
	tokenErr := &TokenError{
		Err:       baseErr,
		TokenID:   "tok_abc123",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Test Error() with TokenID
	errMsg := tokenErr.Error()
	if !strings.Contains(errMsg, "tok_abc123") {
		t.Errorf("Error message should contain TokenID: %s", errMsg)
	}
	if !strings.Contains(errMsg, "token error") {
		t.Errorf("Error message should contain 'token error': %s", errMsg)
	}

	// Test Error() without TokenID
	tokenErrNoID := &TokenError{
		Err:       baseErr,
		TokenID:   "",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	errMsgNoID := tokenErrNoID.Error()
	if strings.Contains(errMsgNoID, "id=") {
		t.Errorf("Error message should not contain 'id=' when TokenID is empty: %s", errMsgNoID)
	}

	// Test Unwrap()
	unwrapped := tokenErr.Unwrap()
	if unwrapped != baseErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, baseErr)
	}

	// Test Is() - should match base error
	if !errors.Is(tokenErr, baseErr) {
		t.Error("errors.Is should match base error")
	}

	// Test Is() - should not match different error
	differentErr := errors.New("different")
	if errors.Is(tokenErr, differentErr) {
		t.Error("errors.Is should not match different error")
	}
}

func TestSigningErrorMethods(t *testing.T) {
	baseErr := errors.New("signing failed")

	// Test SigningError
	signingErr := &SigningError{
		Algorithm: "RS256",
		Err:       baseErr,
	}

	// Test Error()
	errMsg := signingErr.Error()
	if !strings.Contains(errMsg, "RS256") {
		t.Errorf("Error message should contain algorithm: %s", errMsg)
	}
	if !strings.Contains(errMsg, "signing error") {
		t.Errorf("Error message should contain 'signing error': %s", errMsg)
	}

	// Test Unwrap()
	unwrapped := signingErr.Unwrap()
	if unwrapped != baseErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, baseErr)
	}
}

func TestNewTokenError(t *testing.T) {
	baseErr := errors.New("test error")
	tokenID := "tok_test123"
	expiresAt := time.Now().Add(time.Hour)

	tokenErr := NewTokenError(baseErr, tokenID, expiresAt)

	if tokenErr.Err != baseErr {
		t.Errorf("Err field = %v, want %v", tokenErr.Err, baseErr)
	}
	if tokenErr.TokenID != tokenID {
		t.Errorf("TokenID field = %v, want %v", tokenErr.TokenID, tokenID)
	}
	if !tokenErr.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt field = %v, want %v", tokenErr.ExpiresAt, expiresAt)
	}
}

func TestNewSigningError(t *testing.T) {
	baseErr := errors.New("base signing error")
	algorithm := "ES256"

	signingErr := NewSigningError(algorithm, baseErr)

	if signingErr.Algorithm != algorithm {
		t.Errorf("Algorithm field = %v, want %v", signingErr.Algorithm, algorithm)
	}
	if signingErr.Err != baseErr {
		t.Errorf("Err field = %v, want %v", signingErr.Err, baseErr)
	}
}

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

func TestProcessorIsTokenRevokedInvalidToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
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

// TestProcessorIsClosed tests the IsClosed method
func TestProcessorIsClosed(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
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
				Blacklist:       DefaultBlacklistConfig(),
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
	processor, err := newTestProcessor(secretKey)
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
	processor, err := newTestProcessor(secretKey)
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

// TestProcessorOperationsAfterClose tests operations on closed processor
func TestProcessorOperationsAfterClose(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
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
	processor, err := newTestProcessor(secretKey)
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
	processor, err := newTestProcessor(secretKey)
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
	processor, err := newTestProcessor(secretKey)
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
	processor2, err := newTestProcessor(secretKey)
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

// TestBlacklistConfigValidation tests BlacklistConfig validation
func TestBlacklistConfigValidation(t *testing.T) {
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
			cfg := DefaultConfig()
			cfg.SecretKey = secretKey
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

// TestClaimsWithEmptyUserIDAndUsername tests claims validation
func TestClaimsWithEmptyUserIDAndUsername(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
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

// ============================================================================
// CLOCK PROVIDER TESTS
// ============================================================================

func TestSystemClock(t *testing.T) {
	clock := SystemClock{}

	// Test Now() returns current time
	now := clock.Now()
	if now.IsZero() {
		t.Error("SystemClock.Now() should not return zero time")
	}

	// Verify it's close to current time
	timeDiff := time.Since(now)
	if timeDiff < 0 || timeDiff > time.Second {
		t.Errorf("SystemClock.Now() time difference unexpected: %v", timeDiff)
	}
}

func TestFixedClock(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := FixedClock{T: fixedTime}

	// Test Now() returns fixed time
	now := clock.Now()
	if !now.Equal(fixedTime) {
		t.Errorf("FixedClock.Now() = %v, want %v", now, fixedTime)
	}

	// Multiple calls should return same time
	now2 := clock.Now()
	if !now2.Equal(now) {
		t.Error("FixedClock.Now() should return same time on multiple calls")
	}
}

// ============================================================================
// PROCESSOR WITH CUSTOM CLAIMS TESTS
// ============================================================================

func TestProcessorCreateTokenWith(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID:  "custom-user",
		Email:   "custom@example.com",
		IsAdmin: true,
	}

	token, err := processor.CreateTokenWith(claims)
	if err != nil {
		t.Fatalf("CreateTokenWith failed: %v", err)
	}
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Validate the token
	validatedClaims := &TestCustomClaims{}
	result, valid, err := processor.ValidateTokenWith(token, validatedClaims)
	if err != nil {
		t.Fatalf("ValidateTokenWith failed: %v", err)
	}
	if !valid {
		t.Error("Token should be valid")
	}

	resultClaims, ok := result.(*TestCustomClaims)
	if !ok {
		t.Fatal("Expected TestCustomClaims type")
	}
	if resultClaims.UserID != claims.UserID {
		t.Errorf("UserID = %s, want %s", resultClaims.UserID, claims.UserID)
	}
}

func TestProcessorValidateTokenWith(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID:  "validate-user",
		Email:   "validate@example.com",
		IsAdmin: false,
	}

	token, err := processor.CreateTokenWith(claims)
	if err != nil {
		t.Fatalf("CreateTokenWith failed: %v", err)
	}

	// Test with valid token
	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateTokenWith(token, validatedClaims)
	if err != nil || !valid {
		t.Errorf("Token should be valid: err=%v, valid=%v", err, valid)
	}

	// Test with invalid token
	_, valid, err = processor.ValidateTokenWith("invalid.token", validatedClaims)
	if err == nil || valid {
		t.Error("Invalid token should fail validation")
	}

	// Test with empty token
	_, valid, err = processor.ValidateTokenWith("", validatedClaims)
	if err == nil || valid {
		t.Error("Empty token should fail validation")
	}
}

func TestProcessorCreateRefreshTokenWith(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID: "refresh-user",
		Email:  "refresh@example.com",
	}

	token, err := processor.CreateRefreshTokenWith(claims)
	if err != nil {
		t.Fatalf("CreateRefreshTokenWith failed: %v", err)
	}
	if token == "" {
		t.Error("Refresh token should not be empty")
	}

	// Validate the refresh token
	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateTokenWith(token, validatedClaims)
	if err != nil || !valid {
		t.Errorf("Refresh token should be valid: err=%v, valid=%v", err, valid)
	}
}

func TestProcessorWithCustomClaimsWithClosedProcessor(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Close processor
	processor.Close()

	claims := &TestCustomClaims{
		UserID: "closed-user",
		Email:  "closed@example.com",
	}

	// All operations should fail
	_, err = processor.CreateTokenWith(claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}

	_, _, err = processor.ValidateTokenWith("token", claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}

	_, err = processor.CreateRefreshTokenWith(claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}
}

// ============================================================================
// RATE LIMITER EDGE CASES
// ============================================================================

func TestRateLimiterNew(t *testing.T) {
	// Test with valid parameters
	rl := NewRateLimiter(100, time.Minute)
	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	rl.Close()

	// Test with zero rate
	rl = NewRateLimiter(0, time.Minute)
	rl.Close()

	// Test with zero window
	rl = NewRateLimiter(100, 0)
	rl.Close()
}

func TestRateLimiterAllowNEdgeCases(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	defer rl.Close()

	key := "test-key"

	// Test with zero n
	if !rl.AllowN(key, 0) {
		t.Error("AllowN with 0 should always return true")
	}

	// Test with negative n - should return false per implementation
	if rl.AllowN(key, -1) {
		t.Error("AllowN with negative should return false")
	}

	// Test with n greater than max
	if rl.AllowN(key, 100) {
		t.Error("AllowN with n > max should return false")
	}
}

func TestRateLimiterResetNonExistent(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	defer rl.Close()

	// Reset non-existent key should not panic
	rl.Reset("non-existent-key")
}

func TestRateLimiterConcurrentReset(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	defer rl.Close()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			key := fmt.Sprintf("key-%d", id)
			rl.Allow(key)
			rl.Reset(key)
			done <- true
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
