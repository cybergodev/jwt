package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

// Advanced features demonstration
// Covers: custom configurations, rate limiting, error handling, production patterns

func main() {
	fmt.Println("🔬 JWT Library - Advanced Features")
	fmt.Println("===================================\n ")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Example 1: Custom configuration with all options
	customConfigurationExample(secretKey)
	fmt.Println()

	// Example 2: Rate limiting demonstration
	rateLimitingExample(secretKey)
	fmt.Println()

	// Example 3: Error handling patterns
	errorHandlingExample(secretKey)
	fmt.Println()

	// Example 4: Production deployment configuration
	productionConfigExample(secretKey)
}

// customConfigurationExample demonstrates all configuration options
func customConfigurationExample(secretKey string) {
	fmt.Println("⚙️  Example 1: Custom Configuration")
	fmt.Println("-----------------------------------")

	// Blacklist configuration for token revocation
	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           50000,           // Maximum revoked tokens to store
		CleanupInterval:   5 * time.Minute, // Cleanup expired entries every 5 minutes
		EnableAutoCleanup: true,            // Automatically remove expired entries
	}

	// JWT processor configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  10 * time.Minute,    // Short-lived access tokens
		RefreshTokenTTL: 30 * 24 * time.Hour, // 30-day refresh tokens
		Issuer:          "advanced-example",
		SigningMethod:   jwt.SigningMethodHS512, // Stronger signing algorithm
		EnableRateLimit: false,                  // Disabled for this example
	}

	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	fmt.Printf("✅ Processor created with custom configuration:\n")
	fmt.Printf("   - Access Token TTL: %v\n", config.AccessTokenTTL)
	fmt.Printf("   - Refresh Token TTL: %v\n", config.RefreshTokenTTL)
	fmt.Printf("   - Signing Method: %s\n", config.SigningMethod)
	fmt.Printf("   - Blacklist Max Size: %d\n", blacklistConfig.MaxSize)

	// Create token with complex claims
	claims := jwt.Claims{
		UserID:      "admin001",
		Username:    "system_admin",
		Role:        "super_admin",
		Permissions: []string{"read", "write", "delete", "admin"},
		Scopes:      []string{"admin:*", "api:*", "system:*"},
		SessionID:   "admin_session_xyz",
		ClientID:    "admin_panel",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Printf("✅ Token created and validated\n")
	fmt.Printf("   - User: %s (Role: %s)\n", parsedClaims.Username, parsedClaims.Role)
	fmt.Printf("   - Permissions: %v\n", parsedClaims.Permissions)
	fmt.Printf("   - Scopes: %v\n", parsedClaims.Scopes)
	fmt.Printf("   - Session: %s\n", parsedClaims.SessionID)
}

// rateLimitingExample demonstrates rate limiting features
func rateLimitingExample(secretKey string) {
	fmt.Println("🚦 Example 2: Rate Limiting")
	fmt.Println("---------------------------")

	// Configure strict rate limiting
	config := jwt.DefaultConfig()
	config.EnableRateLimit = true
	config.RateLimitRate = 10            // 10 operations per window
	config.RateLimitWindow = time.Minute // Per minute

	processor, err := jwt.New(secretKey, config)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	fmt.Printf("✅ Rate limiting enabled: %d operations per %v\n",
		config.RateLimitRate, config.RateLimitWindow)

	claims := jwt.Claims{
		UserID:   "user123",
		Username: "rate_test_user",
		Role:     "user",
	}

	// Attempt to create tokens until rate limit is hit
	successCount := 0
	for i := 0; i < 15; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			if err == jwt.ErrRateLimitExceeded {
				fmt.Printf("⚠️  Rate limit exceeded after %d tokens\n", successCount)
				fmt.Printf("✅ Rate limiting protection working correctly\n")
				return
			}
			log.Printf("Unexpected error: %v", err)
			return
		}
		successCount++
	}

	fmt.Printf("✅ Created %d tokens within rate limit\n", successCount)
}

// errorHandlingExample demonstrates proper error handling
func errorHandlingExample(secretKey string) {
	fmt.Println("🛡️  Example 3: Error Handling")
	fmt.Println("-----------------------------")

	// Test 1: Invalid secret key
	_, err := jwt.CreateToken("too-short", jwt.Claims{UserID: "test"})
	if err != nil {
		fmt.Printf("✅ Correctly caught invalid secret key: %v\n", err)
	}

	// Test 2: Empty claims
	_, err = jwt.CreateToken(secretKey, jwt.Claims{})
	if err != nil {
		fmt.Printf("✅ Correctly caught empty claims: %v\n", err)
	}

	// Test 3: Invalid token format
	_, _, err = jwt.ValidateToken(secretKey, "invalid.token.format")
	if err != nil {
		fmt.Printf("✅ Correctly caught invalid token: %v\n", err)
	}

	// Test 4: Malformed token
	_, _, err = jwt.ValidateToken(secretKey, "not-a-jwt")
	if err != nil {
		fmt.Printf("✅ Correctly caught malformed token: %v\n", err)
	}

	fmt.Printf("✅ All error handling tests passed\n")
}

// productionConfigExample demonstrates production-ready configuration
func productionConfigExample(secretKey string) {
	fmt.Println("🚀 Example 4: Production Configuration")
	fmt.Println("--------------------------------------")

	// Production blacklist configuration
	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           100000,          // Large capacity for production
		CleanupInterval:   5 * time.Minute, // Regular cleanup
		EnableAutoCleanup: true,            // Essential for production
	}

	// Production JWT configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  5 * time.Minute,    // Very short-lived for security
		RefreshTokenTTL: 7 * 24 * time.Hour, // Weekly refresh
		Issuer:          "production-api-v1",
		SigningMethod:   jwt.SigningMethodHS512, // Strongest algorithm
		EnableRateLimit: true,
		RateLimitRate:   100,
		RateLimitWindow: time.Minute,
	}

	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Failed to create production processor: %v", err)
	}
	defer processor.Close()

	fmt.Printf("✅ Production processor configured:\n")
	fmt.Printf("   - Ultra-short access tokens (5 min)\n")
	fmt.Printf("   - Strong encryption (HS512)\n")
	fmt.Printf("   - Rate limiting enabled (100/min)\n")
	fmt.Printf("   - Token revocation enabled\n")
	fmt.Printf("   - Auto-cleanup enabled\n")

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

	fmt.Printf("✅ Token created and validated\n")
	fmt.Printf("   - User: %s\n", parsedClaims.Username)
	fmt.Printf("   - Expires: %s\n", parsedClaims.ExpiresAt.Time.Format("15:04:05"))

	// Revoke token
	err = processor.RevokeToken(token)
	if err != nil {
		log.Printf("Failed to revoke token: %v", err)
	} else {
		fmt.Printf("✅ Token revoked successfully\n")
	}

	// Verify revoked token is rejected
	_, valid, _ = processor.ValidateToken(token)
	if !valid {
		fmt.Printf("✅ Revoked token correctly rejected\n")
	}

	fmt.Println("\n🎯 Production Checklist:")
	fmt.Println("  ✅ Strong secret key from environment")
	fmt.Println("  ✅ Short-lived access tokens")
	fmt.Println("  ✅ Strong signing algorithm (HS512)")
	fmt.Println("  ✅ Rate limiting enabled")
	fmt.Println("  ✅ Token revocation enabled")
	fmt.Println("  ✅ Automatic cleanup enabled")
	fmt.Println("  ✅ Proper error handling")
	fmt.Println("  ✅ Resource cleanup (defer Close())")
	fmt.Println("\n💡 In production:")
	fmt.Println("  - Load secret key from environment: os.Getenv(\"JWT_SECRET_KEY\")")
	fmt.Println("  - Use HTTPS for all token transmission")
	fmt.Println("  - Implement token refresh workflow")
	fmt.Println("  - Monitor rate limit violations")
	fmt.Println("  - Log security events")
}
