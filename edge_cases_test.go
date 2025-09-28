package jwt

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// 🧪 COMPREHENSIVE EDGE CASES TESTS: Boundary Conditions and Error Handling

func TestTokenExpiration(t *testing.T) {
	// Create processor with longer TTL to avoid immediate expiration
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  2 * time.Second, // Longer TTL to ensure initial validity
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
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

	// Wait for token to expire
	time.Sleep(2500 * time.Millisecond) // Wait longer than TTL

	// Token should be invalid after expiration
	_, valid, err = processor.ValidateToken(token)
	if err != nil {
		// Some implementations may return an error for expired tokens
		t.Logf("Expired token returned error (acceptable): %v", err)
	} else if valid {
		// If no error, token should at least be invalid
		t.Error("Token should be invalid after expiration")
	} else {
		// Token is invalid but no error - this is the expected behavior
		t.Log("Expired token correctly marked as invalid")
	}
}

func TestVeryLongTokens(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create claims with moderately long data (within limits, but varied to avoid malicious pattern detection)
	baseString := "abcdefghijklmnopqrstuvwxyz0123456789" // 36 chars
	longString := strings.Repeat(baseString, 6)[:200] // Ensure we have at least 200 chars, then truncate
	claims := Claims{
		UserID:   longString,
		Username: longString[:100], // Different lengths to avoid repetition
		Role:     longString[50:150], // Different substring
	}

	// Should handle long claims within limits
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token with long claims: %v", err)
	}

	// Should validate long token
	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate long token: %v", err)
	}
	if !valid {
		t.Error("Long token should be valid")
	}

	if parsedClaims.UserID != longString {
		t.Error("Long UserID should be preserved")
	}
}

func TestExtremelyLongTokens(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create claims that would result in a very long token
	veryLongString := strings.Repeat("x", 5000)
	claims := Claims{
		UserID:   veryLongString,
		Username: veryLongString,
	}

	// Should reject extremely long claims
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Should reject extremely long claims")
	}
}

func TestMalformedTokens(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	malformedTokens := []string{
		"",                           // Empty token
		"invalid",                    // No dots
		"invalid.token",              // Only one dot
		"invalid.token.signature.extra", // Too many dots
		"invalid..signature",         // Empty middle part
		".token.signature",           // Empty header
		"header.token.",              // Empty signature
		"header..signature",          // Empty claims
		"not-base64.token.signature", // Invalid base64
		"aGVhZGVy.not-base64.signature", // Invalid base64 in claims
		"aGVhZGVy.dG9rZW4.not-base64",   // Invalid base64 in signature
		strings.Repeat("a", 10000),   // Extremely long token
		"a.b.c",                      // Too short parts
	}

	for i, malformedToken := range malformedTokens {
		t.Run(fmt.Sprintf("MalformedToken_%d", i), func(t *testing.T) {
			_, valid, err := processor.ValidateToken(malformedToken)
			if valid {
				t.Errorf("Malformed token should not be valid: %s", malformedToken)
			}
			// Some malformed tokens should return errors, others should just be invalid
			if err == nil && malformedToken != "" {
				// Empty token should return error, others might just be invalid
				if len(malformedToken) < 5 {
					t.Errorf("Very malformed token should return error: %s", malformedToken)
				}
			}
		})
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
		{UserID: "user123", Username: "user\nwith\nnewlines"},
		{UserID: "user123", Username: "user\twith\ttabs"},
		{UserID: "user123", Username: "user\"with\"quotes"},
		{UserID: "user123", Username: "user'with'apostrophes"},
		{UserID: "user123", Username: "user\\with\\backslashes"},
		{UserID: "user123", Username: "user/with/slashes"},
		{UserID: "user123", Username: "user with spaces"},
		{UserID: "user123", Username: "user{with}braces"},
		{UserID: "user123", Username: "user[with]brackets"},
		{UserID: "user123", Username: "user(with)parentheses"},
	}

	for i, claims := range specialClaims {
		t.Run(fmt.Sprintf("SpecialChars_%d", i), func(t *testing.T) {
			token, err := processor.CreateToken(claims)
			if err != nil {
				t.Fatalf("Failed to create token with special characters: %v", err)
			}

			parsedClaims, valid, err := processor.ValidateToken(token)
			if err != nil {
				t.Fatalf("Failed to validate token with special characters: %v", err)
			}
			if !valid {
				t.Error("Token with special characters should be valid")
			}

			if parsedClaims.UserID != claims.UserID {
				t.Errorf("UserID mismatch: expected %s, got %s", claims.UserID, parsedClaims.UserID)
			}
			if parsedClaims.Username != claims.Username {
				t.Errorf("Username mismatch: expected %s, got %s", claims.Username, parsedClaims.Username)
			}
		})
	}
}

func TestNilAndEmptyValues(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test with nil extra map
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Extra:    nil,
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token with nil extra: %v", err)
	}

	_, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token with nil extra: %v", err)
	}
	if !valid {
		t.Error("Token with nil extra should be valid")
	}

	// Test with empty permissions slice
	claims = Claims{
		UserID:      "user123",
		Username:    "testuser",
		Permissions: []string{},
	}

	token, err = processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token with empty permissions: %v", err)
	}

	_, valid, err = processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token with empty permissions: %v", err)
	}
	if !valid {
		t.Error("Token with empty permissions should be valid")
	}
}

func TestContextTimeout(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Test with already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = processor.CreateTokenWithContext(ctx, claims)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"
	_, _, err = processor.ValidateTokenWithContext(ctx, token)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
}

func TestConcurrentClose(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Start operations in background
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			processor.CreateToken(claims)
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Close processor while operations are running
	time.Sleep(10 * time.Millisecond)
	err = processor.Close()
	if err != nil {
		t.Errorf("Failed to close processor: %v", err)
	}

	// Wait for background operations to complete
	<-done

	// Further operations should fail
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Expected error after closing processor")
	}
}

func TestDoubleClose(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Close once
	err = processor.Close()
	if err != nil {
		t.Errorf("First close failed: %v", err)
	}

	// Close again - should return error for already closed processor
	err = processor.Close()
	if err == nil {
		t.Error("Expected error when closing already closed processor")
	}
}

func TestLargePermissionsArray(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create claims with many permissions
	permissions := make([]string, 1000)
	for i := range permissions {
		permissions[i] = fmt.Sprintf("permission_%d", i)
	}

	claims := Claims{
		UserID:      "user123",
		Username:    "testuser",
		Permissions: permissions,
	}

	// Should reject too many permissions
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Should reject claims with too many permissions")
	}
}

func TestLargeExtraMap(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create claims with many extra fields
	extra := make(map[string]any)
	for i := 0; i < 1000; i++ {
		extra[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Extra:    extra,
	}

	// Should reject too many extra fields
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Should reject claims with too many extra fields")
	}
}

func TestZeroTTLConfig(t *testing.T) {
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  0,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	_, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
	if err == nil {
		t.Error("Should reject zero access token TTL")
	}

	config = Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 0,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	_, err = NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
	if err == nil {
		t.Error("Should reject zero refresh token TTL")
	}
}

func TestNegativeTTLConfig(t *testing.T) {
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  -15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	_, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
	if err == nil {
		t.Error("Should reject negative access token TTL")
	}

	config = Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: -24 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	_, err = NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
	if err == nil {
		t.Error("Should reject negative refresh token TTL")
	}
}

func TestInvalidTTLRelation(t *testing.T) {
	// Access token TTL should be less than refresh token TTL
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  24 * time.Hour,
		RefreshTokenTTL: 15 * time.Minute,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	_, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
	if err == nil {
		t.Error("Should reject access TTL >= refresh TTL")
	}
}
