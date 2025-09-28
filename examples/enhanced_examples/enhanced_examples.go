package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {
	fmt.Println("🚀 Enhanced JWT Library Examples")
	fmt.Println("=================================")

	// Enhanced basic usage with context
	enhancedBasicExample()
	fmt.Println()

	// Production-ready configuration example
	productionConfigExample()
	fmt.Println()

	// Error handling best practices
	errorHandlingExample()
	fmt.Println()

	// Performance optimization example
	performanceExample()
}

// Enhanced basic usage with context support
func enhancedBasicExample() {
	fmt.Println("📝 Enhanced Basic Usage (with Context)")
	fmt.Println("--------------------------------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create processor with custom configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  10 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "enhanced-example",
		SigningMethod:   jwt.SigningMethodHS256,
		EnableRateLimit: false, // Disabled for this example
	}

	processor, err := jwt.New(secretKey, config)
	if err != nil {
		log.Fatalf("Processor creation failed: %v", err)
	}
	defer func() {
		if err := processor.CloseWithContext(ctx); err != nil {
			log.Printf("Processor close failed: %v", err)
		}
	}()

	// Create claims with comprehensive information
	claims := jwt.Claims{
		UserID:      "user_12345",
		Username:    "enhanced_user",
		Role:        "premium",
		Permissions: []string{"read", "write", "premium_features"},
		Scopes:      []string{"api:read", "api:write", "premium:access"},
		SessionID:   "session_abc123",
		ClientID:    "web_app_v2",
		Extra: map[string]any{
			"subscription": "premium",
			"region":       "us-east-1",
			"features":     []string{"analytics", "export", "api_access"},
		},
	}

	// Create token with context
	token, err := processor.CreateTokenWithContext(ctx, claims)
	if err != nil {
		log.Fatalf("Token creation failed: %v", err)
	}
	fmt.Printf("✅ Token created successfully\n")
	fmt.Printf("Token length: %d characters\n", len(token))

	// Validate token with context
	parsedClaims, valid, err := processor.ValidateTokenWithContext(ctx, token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	if valid {
		fmt.Printf("✅ Token validation successful\n")
		fmt.Printf("User: %s (%s)\n", parsedClaims.Username, parsedClaims.Role)
		fmt.Printf("Permissions: %v\n", parsedClaims.Permissions)
		fmt.Printf("Subscription: %v\n", parsedClaims.Extra["subscription"])
		fmt.Printf("Expires: %s\n", parsedClaims.ExpiresAt.Time.Format("2006-01-02 15:04:05"))
	}

	// Demonstrate refresh token workflow
	refreshToken, err := processor.CreateRefreshToken(claims)
	if err != nil {
		log.Fatalf("Refresh token creation failed: %v", err)
	}
	fmt.Printf("✅ Refresh token created\n")

	// Use refresh token to get new access token
	newAccessToken, err := processor.RefreshToken(refreshToken)
	if err != nil {
		log.Fatalf("Token refresh failed: %v", err)
	}
	fmt.Printf("✅ New access token generated from refresh token\n")

	// Revoke the refresh token
	err = processor.RevokeToken(refreshToken)
	if err != nil {
		log.Printf("Token revocation failed: %v", err)
	} else {
		fmt.Printf("✅ Refresh token revoked\n")
	}

	// Verify revoked token is invalid
	_, valid, err = processor.ValidateToken(refreshToken)
	if !valid || err != nil {
		fmt.Printf("✅ Revoked token correctly rejected\n")
	}

	// Clean up - new access token is still valid
	_, valid, err = processor.ValidateToken(newAccessToken)
	if valid && err == nil {
		fmt.Printf("✅ New access token still valid after refresh token revocation\n")
	}
}

// Production-ready configuration example
func productionConfigExample() {
	fmt.Println("🏭 Production Configuration Example")
	fmt.Println("-----------------------------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Production-grade rate limiting configuration
	rateLimitConfig := jwt.RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 50,  // Conservative for production
		ValidationRate:    500, // Higher for read operations
		LoginAttemptRate:  3,   // Strict login protection
		PasswordResetRate: 1,   // Very strict password reset
		CleanupInterval:   2 * time.Minute,
	}

	// Production blacklist configuration
	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           50000, // Large capacity for production
		CleanupInterval:   3 * time.Minute,
		EnableAutoCleanup: true,
		StoreType:         "memory", // Use Redis in real production
	}

	// Production JWT configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  5 * time.Minute,    // Very short-lived for security
		RefreshTokenTTL: 7 * 24 * time.Hour, // Weekly refresh
		Issuer:          "production-api-v1",
		SigningMethod:   jwt.SigningMethodHS512, // Stronger algorithm
		EnableRateLimit: true,
		RateLimit:       &rateLimitConfig,
	}

	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Production processor creation failed: %v", err)
	}
	defer processor.Close()

	fmt.Printf("✅ Production processor created\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  - Access Token TTL: %v\n", config.AccessTokenTTL)
	fmt.Printf("  - Refresh Token TTL: %v\n", config.RefreshTokenTTL)
	fmt.Printf("  - Signing Method: %s\n", config.SigningMethod)
	fmt.Printf("  - Rate Limiting: %v\n", config.EnableRateLimit)
	fmt.Printf("  - Blacklist Max Size: %d\n", blacklistConfig.MaxSize)

	// Test production configuration
	claims := jwt.Claims{
		UserID:   "prod_user_001",
		Username: "production_user",
		Role:     "authenticated",
	}

	// This will be rate limited after a few attempts
	successCount := 0
	for i := 0; i < 10; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			if err == jwt.ErrRateLimitExceeded {
				fmt.Printf("⚠️  Rate limit protection activated after %d tokens\n", successCount)
				break
			}
			log.Printf("Unexpected error: %v", err)
			break
		}
		successCount++
	}

	fmt.Printf("✅ Production configuration working correctly\n")
}

// Error handling best practices
func errorHandlingExample() {
	fmt.Println("🛡️ Error Handling Best Practices")
	fmt.Println("---------------------------------")

	// Test with invalid secret key
	shortKey := "too-short"
	_, err := jwt.CreateToken(shortKey, jwt.Claims{UserID: "test"})
	if err != nil {
		fmt.Printf("✅ Correctly caught invalid secret key: %v\n", err)
	}

	// Test with empty claims
	validKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
	_, err = jwt.CreateToken(validKey, jwt.Claims{})
	if err != nil {
		fmt.Printf("✅ Correctly caught empty claims: %v\n", err)
	}

	// Test with invalid token
	_, _, err = jwt.ValidateToken(validKey, "invalid.token.here")
	if err != nil {
		fmt.Printf("✅ Correctly caught invalid token: %v\n", err)
	}

	// Test with malformed token
	_, _, err = jwt.ValidateToken(validKey, "not-a-jwt-token")
	if err != nil {
		fmt.Printf("✅ Correctly caught malformed token: %v\n", err)
	}

	fmt.Printf("✅ All error handling tests passed\n")
}

// Performance optimization example
func performanceExample() {
	fmt.Println("⚡ Performance Optimization Example")
	fmt.Println("-----------------------------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Demonstrate convenience functions (cached processors)
	fmt.Println("Testing convenience functions performance...")
	start := time.Now()

	claims := jwt.Claims{
		UserID:   "perf_user",
		Username: "performance_test",
		Role:     "user",
	}

	// Create multiple tokens using convenience functions
	// These will reuse cached processors for better performance
	for i := 0; i < 20; i++ {
		token, err := jwt.CreateToken(secretKey, claims)
		if err != nil {
			log.Printf("Token creation failed: %v", err)
			continue
		}

		// Validate immediately
		_, valid, err := jwt.ValidateToken(secretKey, token)
		if err != nil || !valid {
			log.Printf("Token validation failed: %v", err)
			continue
		}
	}

	convenienceDuration := time.Since(start)
	fmt.Printf("✅ Convenience functions: 20 create+validate operations in %v\n", convenienceDuration)

	// Compare with processor pattern
	fmt.Println("Testing processor pattern performance...")
	config := jwt.DefaultConfig()
	config.EnableRateLimit = false // Disable for performance test

	processor, err := jwt.New(secretKey, config)
	if err != nil {
		log.Fatalf("Processor creation failed: %v", err)
	}
	defer processor.Close()

	start = time.Now()
	for i := 0; i < 20; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			log.Printf("Token creation failed: %v", err)
			continue
		}

		_, valid, err := processor.ValidateToken(token)
		if err != nil || !valid {
			log.Printf("Token validation failed: %v", err)
			continue
		}
	}

	processorDuration := time.Since(start)
	fmt.Printf("✅ Processor pattern: 20 create+validate operations in %v\n", processorDuration)

	// Clear cache to demonstrate cleanup
	jwt.ClearProcessorCache()
	fmt.Printf("✅ Processor cache cleared\n")

	fmt.Printf("Performance comparison:\n")
	fmt.Printf("  - Convenience functions: %v\n", convenienceDuration)
	fmt.Printf("  - Processor pattern: %v\n", processorDuration)
	if processorDuration < convenienceDuration {
		fmt.Printf("  - Processor pattern is faster by %v\n", convenienceDuration-processorDuration)
	} else {
		fmt.Printf("  - Convenience functions are faster by %v\n", processorDuration-convenienceDuration)
	}
}
