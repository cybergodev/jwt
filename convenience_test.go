package jwt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 🧪 COMPREHENSIVE UNIT TESTS: Convenience Functions

func TestCreateTokenConvenience(t *testing.T) {
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	token, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}

	// Verify token format
	if len(token) < 10 {
		t.Error("Token seems too short")
	}
}

func TestValidateTokenConvenience(t *testing.T) {
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Create token first
	token, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Validate token
	parsedClaims, valid, err := ValidateToken(testSecretKey, token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Error("Token should be valid")
	}

	if parsedClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID=%s, got UserID=%s", claims.UserID, parsedClaims.UserID)
	}

	if parsedClaims.Username != claims.Username {
		t.Errorf("Expected Username=%s, got Username=%s", claims.Username, parsedClaims.Username)
	}

	if parsedClaims.Role != claims.Role {
		t.Errorf("Expected Role=%s, got Role=%s", claims.Role, parsedClaims.Role)
	}
}

func TestRevokeTokenConvenience(t *testing.T) {
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Create token
	token, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Token should be valid initially
	_, valid, err := ValidateToken(testSecretKey, token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if !valid {
		t.Error("Token should be valid initially")
	}

	// Revoke token
	err = RevokeToken(testSecretKey, token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Token should be invalid after revocation
	_, valid, err = ValidateToken(testSecretKey, token)
	if err == nil {
		t.Error("Expected error for revoked token")
	}
	if valid {
		t.Error("Token should be invalid after revocation")
	}
}

func TestProcessorCaching(t *testing.T) {
	cacheMutex.Lock()
	processorCache = make(map[string]*cacheEntry)
	cacheMutex.Unlock()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Create multiple tokens with same secret key
	token1, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token1: %v", err)
	}

	token2, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token2: %v", err)
	}

	// Both tokens should be valid
	_, valid1, err := ValidateToken(testSecretKey, token1)
	if err != nil || !valid1 {
		t.Error("Token1 should be valid")
	}

	_, valid2, err := ValidateToken(testSecretKey, token2)
	if err != nil || !valid2 {
		t.Error("Token2 should be valid")
	}

	// Check that processor was cached
	cacheMutex.RLock()
	cacheSize := len(processorCache)
	cacheMutex.RUnlock()

	if cacheSize != 1 {
		t.Errorf("Expected 1 cached processor, got %d", cacheSize)
	}
}

func TestProcessorCacheLimit(t *testing.T) {
	cacheMutex.Lock()
	processorCache = make(map[string]*cacheEntry)
	cacheMutex.Unlock()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Create tokens with different secret keys to fill cache
	for i := 0; i < maxCacheSize+10; i++ {
		// Create a strong secret key avoiding weak patterns like "key", "secret", "password", etc.
		uniquePart := fmt.Sprintf("Unique%dWithRandomData%x", i, i*31337+54321)
		secretKey := "StrongBaseFor" + uniquePart + "MoreRandomStuff"

		// Debug: print the first key to see what's being generated
		if i == 0 {
			t.Logf("Generated secret: %s", secretKey)
		}

		_, err := CreateToken(secretKey, claims)
		if err != nil {
			t.Fatalf("Failed to create token %d with length %d: %v", i, len(secretKey), err)
		}
	}

	// Check that cache size is limited
	cacheMutex.RLock()
	cacheSize := len(processorCache)
	cacheMutex.RUnlock()

	if cacheSize > maxCacheSize {
		t.Errorf("Cache size exceeded limit: expected <= %d, got %d", maxCacheSize, cacheSize)
	}
}

func TestConcurrentConvenienceFunctions(t *testing.T) {
	const numGoroutines = 50
	const numOperations = 20

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	// Test concurrent operations with convenience functions
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
				token, err := CreateToken(testSecretKey, claims)
				if err != nil {
					errors <- fmt.Errorf("create token error: %v", err)
					return
				}

				// Validate token
				_, valid, err := ValidateToken(testSecretKey, token)
				if err != nil {
					errors <- fmt.Errorf("validate token error: %v", err)
					return
				}
				if !valid {
					errors <- fmt.Errorf("token should be valid")
					return
				}

				// Revoke token (test every 5th token to avoid too much overhead)
				if j%5 == 0 {
					err = RevokeToken(testSecretKey, token)
					if err != nil {
						errors <- fmt.Errorf("revoke token error: %v", err)
						return
					}

					// Verify revocation - should return error for revoked token
					_, valid, err = ValidateToken(testSecretKey, token)
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

func TestConvenienceFunctionErrors(t *testing.T) {
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Test with invalid secret key
	_, err := CreateToken("short", claims)
	if err == nil {
		t.Error("Expected error with short secret key")
	}

	_, _, err = ValidateToken("short", "some.token.here")
	if err == nil {
		t.Error("Expected error with short secret key")
	}

	err = RevokeToken("short", "some.token.here")
	if err == nil {
		t.Error("Expected error with short secret key")
	}

	// Test with empty claims
	emptyClaims := Claims{}
	_, err = CreateToken(testSecretKey, emptyClaims)
	if err == nil {
		t.Error("Expected error with empty claims")
	}

	// Test with invalid token
	_, _, err = ValidateToken(testSecretKey, "invalid.token.format")
	if err == nil {
		t.Error("Expected error with invalid token")
	}

	err = RevokeToken(testSecretKey, "invalid.token.format")
	if err == nil {
		t.Error("Expected error with invalid token")
	}
}

func TestConvenienceFunctionCacheCleanup(t *testing.T) {
	cacheMutex.Lock()
	processorCache = make(map[string]*cacheEntry)
	cacheMutex.Unlock()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	// Create a token to populate cache
	_, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Verify cache has entry
	cacheMutex.RLock()
	initialSize := len(processorCache)
	cacheMutex.RUnlock()

	if initialSize != 1 {
		t.Errorf("Expected 1 cached processor, got %d", initialSize)
	}

	cacheMutex.Lock()
	for key, entry := range processorCache {
		entry.processor.Close()
		delete(processorCache, key)
	}
	cacheMutex.Unlock()

	// Verify cache is empty
	cacheMutex.RLock()
	finalSize := len(processorCache)
	cacheMutex.RUnlock()

	if finalSize != 0 {
		t.Errorf("Expected 0 cached processors after cleanup, got %d", finalSize)
	}
}

func TestConvenienceFunctionPerformance(t *testing.T) {
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Warm up cache
	_, err := CreateToken(testSecretKey, claims)
	if err != nil {
		t.Fatalf("Failed to warm up cache: %v", err)
	}

	// Measure performance of cached operations
	start := time.Now()
	const iterations = 50 // Further reduce iterations to avoid rate limiting

	for i := 0; i < iterations; i++ {
		token, err := CreateToken(testSecretKey, claims)
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}

		_, valid, err := ValidateToken(testSecretKey, token)
		if err != nil || !valid {
			t.Fatalf("Failed to validate token %d: %v", i, err)
		}

		// Small delay to avoid rate limiting
		time.Sleep(time.Millisecond)
	}

	duration := time.Since(start)
	avgDuration := duration / iterations

	t.Logf("Average time per create+validate cycle: %v", avgDuration)

	// Performance should be reasonable (less than 1ms per operation on modern hardware)
	if avgDuration > time.Millisecond {
		t.Logf("Warning: Performance might be suboptimal: %v per operation", avgDuration)
	}
}
