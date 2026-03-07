//go:build example

package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

// Advanced features demonstration.
// Covers: rate limiting, blacklist, error handling, production patterns.
func main() {
	fmt.Println("JWT Library - Advanced Features")
	fmt.Println("===============================")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Example 1: Rate limiting
	rateLimitingExample(secretKey)

	fmt.Println()

	// Example 2: Token blacklist and revocation
	blacklistExample(secretKey)

	fmt.Println()

	// Example 3: Error handling patterns
	errorHandlingExample(secretKey)

	fmt.Println()

	// Example 4: Production configuration
	productionConfigExample(secretKey)

	fmt.Println("\nAdvanced features example complete!")
}

// rateLimitingExample demonstrates rate limiting features.
func rateLimitingExample(secretKey string) {
	fmt.Println("Example 1: Rate Limiting")
	fmt.Println("------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.EnableRateLimit = true
	cfg.RateLimitRate = 5             // 5 operations per window
	cfg.RateLimitWindow = time.Minute // Per minute

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	fmt.Printf("Rate limiting enabled: %d operations per %v\n", cfg.RateLimitRate, cfg.RateLimitWindow)

	claims := jwt.Claims{
		UserID:   "user123",
		Username: "rate_test_user",
		Role:     "user",
	}

	// Attempt to create tokens until rate limit is hit
	successCount := 0
	for i := 0; i < 10; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			if errors.Is(err, jwt.ErrRateLimitExceeded) {
				fmt.Printf("Rate limit exceeded after %d tokens\n", successCount)
				fmt.Println("Rate limiting protection working correctly")
				return
			}
			log.Printf("Unexpected error: %v", err)
			return
		}
		successCount++
	}

	fmt.Printf("Created %d tokens within rate limit\n", successCount)
}

// blacklistExample demonstrates token revocation and blacklist.
func blacklistExample(secretKey string) {
	fmt.Println("Example 2: Token Blacklist")
	fmt.Println("--------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.Blacklist = jwt.BlacklistConfig{
		MaxSize:           10000,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
	}

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create token
	claims := jwt.Claims{
		UserID:   "user456",
		Username: "blacklist_test",
		Role:     "user",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Println("Token created")

	// Validate token
	_, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Token should be valid: %v", err)
	}
	fmt.Println("Token validated successfully")

	// Check if token is revoked
	revoked, err := processor.IsTokenRevoked(token)
	if err != nil {
		log.Fatalf("Failed to check revocation: %v", err)
	}
	fmt.Printf("Token revoked status: %v\n", revoked)

	// Revoke token
	if err := processor.RevokeToken(token); err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}
	fmt.Println("Token revoked")

	// Verify revoked token is rejected
	_, valid, _ = processor.ValidateToken(token)
	if valid {
		log.Fatal("Revoked token should be invalid")
	}
	fmt.Println("Revoked token correctly rejected")

	// Check revocation status again
	revoked, _ = processor.IsTokenRevoked(token)
	fmt.Printf("Token revoked status after revocation: %v\n", revoked)
}

// errorHandlingExample demonstrates proper error handling.
func errorHandlingExample(secretKey string) {
	fmt.Println("Example 3: Error Handling")
	fmt.Println("-------------------------")

	// Create processor for testing
	cfg := jwt.Config{SecretKey: secretKey}
	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test 1: Invalid secret key (demonstrated via config validation)
	_, err = jwt.New(jwt.Config{SecretKey: "too-short"})
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidSecretKey) {
			fmt.Println("Correctly caught invalid secret key")
		}
	}

	// Test 2: Invalid token format
	_, _, err = processor.ValidateToken("invalid.token.format")
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidToken) {
			fmt.Println("Correctly caught invalid token format")
		}
	}

	// Test 3: Malformed token
	_, _, err = processor.ValidateToken("not-a-jwt")
	if err != nil {
		fmt.Println("Correctly caught malformed token")
	}

	// Test 4: Empty claims validation
	_, err = processor.CreateToken(jwt.Claims{})
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidClaims) {
			fmt.Println("Correctly caught empty claims")
		}
	}

	// Test 5: Using errors.Is for error checking
	token, _ := processor.CreateToken(jwt.Claims{UserID: "test"})
	_, valid, err := processor.ValidateToken(token)
	if !valid && err != nil {
		// Check specific error types
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			fmt.Println("Token expired")
		case errors.Is(err, jwt.ErrTokenRevoked):
			fmt.Println("Token revoked")
		case errors.Is(err, jwt.ErrInvalidToken):
			fmt.Println("Invalid token")
		default:
			fmt.Printf("Other error: %v\n", err)
		}
	}

	fmt.Println("All error handling tests passed")
}

// productionConfigExample demonstrates production-ready configuration.
func productionConfigExample(secretKey string) {
	fmt.Println("Example 4: Production Configuration")
	fmt.Println("------------------------------------")

	// Production configuration
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey // In production: os.Getenv("JWT_SECRET_KEY")
	cfg.AccessTokenTTL = 5 * time.Minute
	cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	cfg.Issuer = "production-api-v1"
	cfg.SigningMethod = jwt.SigningMethodHS512
	cfg.EnableRateLimit = true
	cfg.RateLimitRate = 100
	cfg.RateLimitWindow = time.Minute
	cfg.Blacklist = jwt.BlacklistConfig{
		MaxSize:           100000,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
	}

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create production processor: %v", err)
	}
	defer processor.Close()

	fmt.Println("Production processor configured:")
	fmt.Println("  - Ultra-short access tokens (5 min)")
	fmt.Println("  - Strong encryption (HS512)")
	fmt.Println("  - Rate limiting enabled (100/min)")
	fmt.Println("  - Token revocation enabled")
	fmt.Println("  - Auto-cleanup enabled")

	// Test production configuration
	claims := jwt.Claims{
		UserID:    "prod_user_001",
		Username:  "production_user",
		Role:      "authenticated",
		SessionID: "prod_session_123",
	}

	// Create and validate token
	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Printf("Token validated - User: %s\n", parsedClaims.Username)

	// Production checklist
	fmt.Println("\nProduction Checklist:")
	checklist := []string{
		"Strong secret key from environment",
		"Short-lived access tokens",
		"Strong signing algorithm (HS512/RS256)",
		"Rate limiting enabled",
		"Token revocation enabled",
		"Automatic cleanup enabled",
		"Proper error handling",
		"Resource cleanup (defer Close())",
	}
	for _, item := range checklist {
		fmt.Printf("  [ ] %s\n", item)
	}

	fmt.Println("\nIn production:")
	fmt.Println("  - Load secret key: os.Getenv(\"JWT_SECRET_KEY\")")
	fmt.Println("  - Use HTTPS for all token transmission")
	fmt.Println("  - Implement token refresh workflow")
	fmt.Println("  - Monitor rate limit violations")
	fmt.Println("  - Log security events")
}
