package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {
	fmt.Println("🏆 JWT Library Best Practices Guide")
	fmt.Println("====================================")

	// Security best practices
	securityBestPractices()
	fmt.Println()

	// Configuration best practices
	configurationBestPractices()
	fmt.Println()

	// Resource management best practices
	resourceManagementBestPractices()
	fmt.Println()

	// Production deployment best practices
	productionBestPractices()
}

// Security best practices
func securityBestPractices() {
	fmt.Println("🔒 Security Best Practices")
	fmt.Println("--------------------------")

	// ✅ DO: Use strong secret keys from environment variables
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		// For demo purposes only - never hardcode in production
		secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
		fmt.Printf("⚠️  Using demo secret key - use environment variable in production\n")
	}

	// ✅ DO: Use short-lived access tokens
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  5 * time.Minute, // Short-lived for security
		RefreshTokenTTL: 24 * time.Hour,  // Reasonable refresh window
		Issuer:          "secure-api-v1",
		SigningMethod:   jwt.SigningMethodHS512, // Stronger algorithm
	}

	processor, err := jwt.New(secretKey, config)
	if err != nil {
		log.Fatalf("Processor creation failed: %v", err)
	}
	defer processor.Close()

	// ✅ DO: Include minimal necessary claims
	claims := jwt.Claims{
		UserID:      "user_12345",
		Username:    "secure_user",
		Role:        "user",
		Permissions: []string{"read", "write"}, // Only necessary permissions
		SessionID:   "session_abc123",
		// ❌ DON'T: Include sensitive data like passwords, SSNs, etc.
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Token creation failed: %v", err)
	}

	fmt.Printf("✅ Secure token created with:\n")
	fmt.Printf("  - Strong secret key (64+ chars)\n")
	fmt.Printf("  - Short TTL (5 minutes)\n")
	fmt.Printf("  - Strong algorithm (HS512)\n")
	fmt.Printf("  - Minimal claims\n")

	// ✅ DO: Always validate tokens before use
	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}

	fmt.Printf("✅ Token validated successfully\n")
	fmt.Printf("  - User: %s\n", parsedClaims.Username)
	fmt.Printf("  - Expires: %s\n", parsedClaims.ExpiresAt.Time.Format("15:04:05"))

	// ✅ DO: Revoke tokens when user logs out
	err = processor.RevokeToken(token)
	if err != nil {
		log.Printf("Token revocation failed: %v", err)
	} else {
		fmt.Printf("✅ Token revoked on logout\n")
	}
}

// Configuration best practices
func configurationBestPractices() {
	fmt.Println("⚙️ Configuration Best Practices")
	fmt.Println("-------------------------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// ✅ DO: Configure appropriate rate limits for your use case
	rateLimitConfig := jwt.RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 100,  // Adjust based on your traffic
		ValidationRate:    1000, // Higher for read operations
		LoginAttemptRate:  5,    // Prevent brute force attacks
		PasswordResetRate: 3,    // Prevent abuse
		CleanupInterval:   5 * time.Minute,
	}

	// ✅ DO: Configure blacklist for token revocation
	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           10000, // Adjust based on your user base
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,     // Always enable for production
		StoreType:         "memory", // Use Redis for distributed systems
	}

	// ✅ DO: Use environment-specific configurations
	var config jwt.Config
	if os.Getenv("ENVIRONMENT") == "production" {
		config = jwt.Config{
			SecretKey:       secretKey,
			AccessTokenTTL:  5 * time.Minute,    // Very short for production
			RefreshTokenTTL: 7 * 24 * time.Hour, // Weekly refresh
			Issuer:          "production-api",
			SigningMethod:   jwt.SigningMethodHS512, // Strongest algorithm
			EnableRateLimit: true,
			RateLimit:       &rateLimitConfig,
		}
	} else {
		config = jwt.Config{
			SecretKey:       secretKey,
			AccessTokenTTL:  30 * time.Minute, // Longer for development
			RefreshTokenTTL: 24 * time.Hour,   // Daily refresh
			Issuer:          "development-api",
			SigningMethod:   jwt.SigningMethodHS256, // Sufficient for dev
			EnableRateLimit: false,                  // Disabled for easier development
		}
	}

	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Processor creation failed: %v", err)
	}
	defer processor.Close()

	fmt.Printf("✅ Environment-specific configuration applied:\n")
	fmt.Printf("  - Access Token TTL: %v\n", config.AccessTokenTTL)
	fmt.Printf("  - Signing Method: %s\n", config.SigningMethod)
	fmt.Printf("  - Rate Limiting: %v\n", config.EnableRateLimit)
	fmt.Printf("  - Blacklist Enabled: true\n")

	// Test the configuration
	claims := jwt.Claims{
		UserID:   "config_test_user",
		Username: "config_user",
		Role:     "user",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Printf("Token creation failed: %v", err)
	} else {
		fmt.Printf("✅ Configuration test successful\n")
	}

	// Clean up
	if token != "" {
		processor.RevokeToken(token)
	}
}

// Resource management best practices
func resourceManagementBestPractices() {
	fmt.Println("🧹 Resource Management Best Practices")
	fmt.Println("-------------------------------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// ✅ DO: Always close processors to free resources
	fmt.Println("Demonstrating proper resource cleanup...")

	processor, err := jwt.New(secretKey)
	if err != nil {
		log.Fatalf("Processor creation failed: %v", err)
	}

	// ✅ DO: Use defer for guaranteed cleanup
	defer func() {
		fmt.Printf("✅ Cleaning up processor resources...\n")
		if err := processor.Close(); err != nil {
			log.Printf("Processor close failed: %v", err)
		} else {
			fmt.Printf("✅ Processor closed successfully\n")
		}
	}()

	// ✅ DO: Use context for timeout control
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	claims := jwt.Claims{
		UserID:   "resource_test_user",
		Username: "resource_user",
		Role:     "user",
	}

	// Create token with context
	token, err := processor.CreateTokenWithContext(ctx, claims)
	if err != nil {
		log.Fatalf("Token creation failed: %v", err)
	}

	// Validate token with context
	_, valid, err := processor.ValidateTokenWithContext(ctx, token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}

	fmt.Printf("✅ Context-aware operations completed\n")

	// ✅ DO: Clear caches when appropriate
	jwt.ClearProcessorCache()
	fmt.Printf("✅ Processor cache cleared\n")

	// ✅ DO: Use graceful shutdown with context
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := processor.CloseWithContext(shutdownCtx); err != nil {
		log.Printf("Graceful shutdown failed: %v", err)
	} else {
		fmt.Printf("✅ Graceful shutdown completed\n")
	}
}

// Production deployment best practices
func productionBestPractices() {
	fmt.Println("🚀 Production Deployment Best Practices")
	fmt.Println("---------------------------------------")

	// ✅ DO: Load configuration from environment
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
		fmt.Printf("⚠️  Using demo secret - set JWT_SECRET_KEY environment variable\n")
	}

	// ✅ DO: Use production-grade configuration
	rateLimitConfig := jwt.RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 50,  // Conservative for production
		ValidationRate:    500, // Higher for API calls
		LoginAttemptRate:  3,   // Strict login protection
		PasswordResetRate: 1,   // Very strict password reset
		CleanupInterval:   2 * time.Minute,
	}

	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           100000, // Large capacity for production
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
		StoreType:         "memory", // Use Redis in distributed systems
	}

	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  5 * time.Minute,    // Very short for security
		RefreshTokenTTL: 7 * 24 * time.Hour, // Weekly refresh
		Issuer:          "production-api-v1",
		SigningMethod:   jwt.SigningMethodHS512, // Strongest available
		EnableRateLimit: true,
		RateLimit:       &rateLimitConfig,
	}

	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Production processor creation failed: %v", err)
	}
	defer processor.Close()

	fmt.Printf("✅ Production processor configured:\n")
	fmt.Printf("  - Ultra-short access tokens (5 min)\n")
	fmt.Printf("  - Strong encryption (HS512)\n")
	fmt.Printf("  - Rate limiting enabled\n")
	fmt.Printf("  - Token revocation enabled\n")
	fmt.Printf("  - Auto-cleanup enabled\n")

	// ✅ DO: Test production configuration
	claims := jwt.Claims{
		UserID:    "prod_user_001",
		Username:  "production_user",
		Role:      "authenticated",
		SessionID: "prod_session_123",
	}

	// Test rate limiting
	successCount := 0
	for i := 0; i < 10; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			if err == jwt.ErrRateLimitExceeded {
				fmt.Printf("✅ Rate limiting activated after %d tokens (production protection working)\n", successCount)
				break
			}
			log.Printf("Unexpected error: %v", err)
			break
		}
		successCount++
	}

	fmt.Printf("✅ Production configuration validated\n")
	fmt.Printf("\n🎯 Production Checklist:\n")
	fmt.Printf("  ✅ Strong secret key from environment\n")
	fmt.Printf("  ✅ Short-lived access tokens\n")
	fmt.Printf("  ✅ Strong signing algorithm\n")
	fmt.Printf("  ✅ Rate limiting enabled\n")
	fmt.Printf("  ✅ Token revocation enabled\n")
	fmt.Printf("  ✅ Automatic cleanup enabled\n")
	fmt.Printf("  ✅ Proper error handling\n")
	fmt.Printf("  ✅ Resource cleanup\n")
	fmt.Printf("  ✅ Context-aware operations\n")
	fmt.Printf("  ✅ Environment-specific configuration\n")
}
