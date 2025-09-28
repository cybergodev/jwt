package jwt

import (
	"testing"
	"time"
)

// TestConvenienceMethodsNoRateLimit tests that convenience methods don't apply rate limiting
func TestConvenienceMethodsNoRateLimit(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
	
	claims := Claims{
		UserID:   "test-user",
		Username: "testuser",
		Role:     "user",
	}

	// Test that we can create many tokens quickly without rate limiting
	for i := 0; i < 200; i++ {
		token, err := CreateToken(secretKey, claims)
		if err != nil {
			t.Fatalf("CreateToken failed on iteration %d: %v", i, err)
		}
		
		// Validate the token
		parsedClaims, valid, err := ValidateToken(secretKey, token)
		if err != nil {
			t.Fatalf("ValidateToken failed on iteration %d: %v", i, err)
		}
		
		if !valid {
			t.Fatalf("Token should be valid on iteration %d", i)
		}
		
		if parsedClaims.UserID != claims.UserID {
			t.Fatalf("UserID mismatch on iteration %d: expected %s, got %s", i, claims.UserID, parsedClaims.UserID)
		}
		
		// Revoke the token
		err = RevokeToken(secretKey, token)
		if err != nil {
			t.Fatalf("RevokeToken failed on iteration %d: %v", i, err)
		}
	}
}

// TestProcessorWithRateLimit tests that processor mode can have rate limiting
func TestProcessorWithRateLimit(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Create a processor with very strict rate limiting
	rateLimitConfig := RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 5,  // Only 5 tokens per minute
		ValidationRate:    10, // Only 10 validations per minute
		LoginAttemptRate:  2,  // Only 2 login attempts per minute
		PasswordResetRate: 1,  // Only 1 password reset per hour
		CleanupInterval:   1 * time.Minute,
	}

	// Create config with rate limiting enabled
	config := DefaultConfig()
	config.EnableRateLimit = true
	config.RateLimit = &rateLimitConfig

	processor, err := New(secretKey, config)
	if err != nil {
		t.Fatalf("Failed to create processor with rate limit: %v", err)
	}
	defer processor.Close()
	
	claims := Claims{
		UserID:   "test-user",
		Username: "testuser",
		Role:     "user",
	}
	
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
		t.Fatalf("Expected to create at least some tokens before hitting rate limit")
	}
	
	t.Logf("Successfully created %d tokens before hitting rate limit", successCount)
}

// TestProcessorWithoutRateLimit tests that processor can be created without rate limiting
func TestProcessorWithoutRateLimit(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Create config with rate limiting explicitly disabled
	config := DefaultConfig()
	config.EnableRateLimit = false

	processor, err := New(secretKey, config)
	if err != nil {
		t.Fatalf("Failed to create processor without rate limit: %v", err)
	}
	defer processor.Close()
	
	claims := Claims{
		UserID:   "test-user",
		Username: "testuser",
		Role:     "user",
	}
	
	// Test that we can create many tokens quickly without rate limiting
	for i := 0; i < 100; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			t.Fatalf("CreateToken failed on iteration %d: %v", i, err)
		}
		
		// Validate the token
		parsedClaims, valid, err := processor.ValidateToken(token)
		if err != nil {
			t.Fatalf("ValidateToken failed on iteration %d: %v", i, err)
		}
		
		if !valid {
			t.Fatalf("Token should be valid on iteration %d", i)
		}
		
		if parsedClaims.UserID != claims.UserID {
			t.Fatalf("UserID mismatch on iteration %d: expected %s, got %s", i, claims.UserID, parsedClaims.UserID)
		}
	}
}

// TestProcessorRateLimitConfiguration tests different rate limit configurations
func TestProcessorRateLimitConfiguration(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
	
	// Test with disabled rate limiting
	config1 := DefaultConfig()
	config1.EnableRateLimit = false

	processor1, err := New(secretKey, config1)
	if err != nil {
		t.Fatalf("Failed to create processor with disabled rate limit: %v", err)
	}
	defer processor1.Close()
	
	claims := Claims{
		UserID:   "test-user",
		Username: "testuser",
		Role:     "user",
	}
	
	// Should be able to create many tokens when rate limiting is disabled
	for i := 0; i < 50; i++ {
		_, err := processor1.CreateToken(claims)
		if err != nil {
			t.Fatalf("CreateToken failed with disabled rate limit on iteration %d: %v", i, err)
		}
	}
	
	// Test with custom rate limiting configuration
	customRateLimitConfig := RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 20,  // 20 tokens per minute
		ValidationRate:    100, // 100 validations per minute
		LoginAttemptRate:  5,   // 5 login attempts per minute
		PasswordResetRate: 2,   // 2 password resets per hour
		CleanupInterval:   30 * time.Second,
	}

	config2 := DefaultConfig()
	config2.EnableRateLimit = true
	config2.RateLimit = &customRateLimitConfig

	processor2, err := New(secretKey, config2)
	if err != nil {
		t.Fatalf("Failed to create processor with custom rate limit: %v", err)
	}
	defer processor2.Close()
	
	// Should be able to create up to 20 tokens
	successCount := 0
	for i := 0; i < 25; i++ {
		_, err := processor2.CreateToken(claims)
		if err != nil {
			if err == ErrRateLimitExceeded {
				break
			}
			t.Fatalf("Unexpected error on iteration %d: %v", i, err)
		}
		successCount++
	}
	
	// Should have created around 20 tokens (allowing for some variance)
	if successCount < 15 || successCount > 25 {
		t.Fatalf("Expected to create around 20 tokens, but created %d", successCount)
	}
	
	t.Logf("Successfully created %d tokens with custom rate limit", successCount)
}

// TestProcessorWithBlacklistAndRateLimit tests processor with both blacklist and rate limiting
func TestProcessorWithBlacklistAndRateLimit(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	rateLimitConfig := RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 10,
		ValidationRate:    50,
		LoginAttemptRate:  3,
		PasswordResetRate: 1,
		CleanupInterval:   1 * time.Minute,
	}

	blacklistConfig := DefaultBlacklistConfig()

	config := DefaultConfig()
	config.EnableRateLimit = true
	config.RateLimit = &rateLimitConfig

	processor, err := NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		t.Fatalf("Failed to create processor with rate limit and blacklist: %v", err)
	}
	defer processor.Close()
	
	claims := Claims{
		UserID:   "test-user",
		Username: "testuser",
		Role:     "user",
	}
	
	// Create a token
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}
	
	// Validate the token
	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	
	if !valid {
		t.Fatalf("Token should be valid")
	}
	
	if parsedClaims.UserID != claims.UserID {
		t.Fatalf("UserID mismatch: expected %s, got %s", claims.UserID, parsedClaims.UserID)
	}
	
	// Revoke the token
	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}
	
	// Try to validate the revoked token
	_, valid, err = processor.ValidateToken(token)
	if err == nil && valid {
		t.Fatalf("Revoked token should not be valid")
	}
}
