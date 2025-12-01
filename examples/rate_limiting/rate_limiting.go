package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	fmt.Println("=== JWT Rate Limiting Examples ===")

	// Example 1: Convenience Methods (No Rate Limiting)
	fmt.Println("1. Convenience Methods (No Rate Limiting)")
	demonstrateConvenienceMethods(secretKey)

	// Example 2: Processor with Rate Limiting
	fmt.Println("\n2. Processor with Rate Limiting")
	demonstrateProcessorWithRateLimit(secretKey)

	// Example 3: Processor without Rate Limiting
	fmt.Println("\n3. Processor without Rate Limiting")
	demonstrateProcessorWithoutRateLimit(secretKey)

	// Example 4: Custom Rate Limit Configuration
	fmt.Println("\n4. Custom Rate Limit Configuration")
	demonstrateCustomRateLimit(secretKey)

	// Example 5: Production Setup with Both Rate Limiting and Blacklist
	fmt.Println("\n5. Production Setup (Rate Limiting + Blacklist)")
	demonstrateProductionSetup(secretKey)
}

func demonstrateConvenienceMethods(secretKey string) {
	claims := jwt.Claims{
		UserID:   "user123",
		Username: "john_doe",
		Role:     "user",
	}

	fmt.Println("Creating 50 tokens rapidly using convenience methods...")
	start := time.Now()

	for i := 0; i < 50; i++ {
		token, err := jwt.CreateToken(secretKey, claims)
		if err != nil {
			log.Printf("Failed to create token %d: %v", i+1, err)
			return
		}

		// Validate the token
		_, valid, err := jwt.ValidateToken(secretKey, token)
		if err != nil || !valid {
			log.Printf("Failed to validate token %d: %v", i+1, err)
			return
		}

		// Revoke the token
		err = jwt.RevokeToken(secretKey, token)
		if err != nil {
			log.Printf("Failed to revoke token %d: %v", i+1, err)
			return
		}
	}

	duration := time.Since(start)
	fmt.Printf("✅ Successfully created, validated, and revoked 50 tokens in %v\n", duration)
	fmt.Println("   No rate limiting applied - perfect for internal services!")
}

func demonstrateProcessorWithRateLimit(secretKey string) {
	// Configure strict rate limiting
	// Create config with rate limiting enabled
	config := jwt.DefaultConfig()
	config.EnableRateLimit = true
	config.RateLimitRate = 10
	config.RateLimitWindow = time.Minute

	processor, err := jwt.New(secretKey, config)
	if err != nil {
		log.Fatalf("Failed to create rate limited processor: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:   "user123",
		Username: "john_doe",
		Role:     "user",
	}

	fmt.Println("Attempting to create tokens with rate limiting...")
	successCount := 0
	rateLimitHit := false

	for i := 0; i < 15; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			if err == jwt.ErrRateLimitExceeded {
				fmt.Printf("⚠️  Rate limit exceeded after %d tokens\n", successCount)
				rateLimitHit = true
				break
			}
			log.Printf("Unexpected error: %v", err)
			return
		}
		successCount++
	}

	if rateLimitHit {
		fmt.Printf("✅ Rate limiting working correctly - protected after %d tokens\n", successCount)
	} else {
		fmt.Printf("✅ Created %d tokens within rate limit\n", successCount)
	}
}

func demonstrateProcessorWithoutRateLimit(secretKey string) {
	// Create config with rate limiting explicitly disabled
	config := jwt.DefaultConfig()
	config.EnableRateLimit = false

	processor, err := jwt.New(secretKey, config)
	if err != nil {
		log.Fatalf("Failed to create processor without rate limit: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:   "user123",
		Username: "john_doe",
		Role:     "user",
	}

	fmt.Println("Creating 100 tokens rapidly without rate limiting...")
	start := time.Now()

	for i := 0; i < 100; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			log.Printf("Failed to create token %d: %v", i+1, err)
			return
		}
	}

	duration := time.Since(start)
	fmt.Printf("✅ Successfully created 100 tokens in %v\n", duration)
	fmt.Println("   No rate limiting - ideal for high-throughput internal services!")
}

func demonstrateCustomRateLimit(secretKey string) {
	// Custom configuration for different use cases
	config := jwt.DefaultConfig()
	config.EnableRateLimit = true
	config.RateLimitRate = 30
	config.RateLimitWindow = time.Minute

	processor, err := jwt.New(secretKey, config)
	if err != nil {
		log.Fatalf("Failed to create custom rate limited processor: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:   "user123",
		Username: "john_doe",
		Role:     "user",
	}

	fmt.Println("Testing custom rate limit configuration...")
	successCount := 0

	for i := 0; i < 35; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			if err == jwt.ErrRateLimitExceeded {
				fmt.Printf("⚠️  Custom rate limit exceeded after %d tokens\n", successCount)
				break
			}
			log.Printf("Unexpected error: %v", err)
			return
		}
		successCount++
	}

	fmt.Printf("✅ Custom rate limiting allowed %d tokens (limit: 30/min)\n", successCount)
}

func demonstrateProductionSetup(secretKey string) {
	// Production-ready configuration
	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           10000, // 10K revoked tokens
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
	}

	config := jwt.DefaultConfig()
	config.EnableRateLimit = true
	config.RateLimitRate = 100
	config.RateLimitWindow = time.Minute

	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Failed to create production processor: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:      "user123",
		Username:    "john_doe",
		Role:        "admin",
		Permissions: []string{"read", "write", "admin"},
	}

	fmt.Println("Production setup with rate limiting and blacklist...")

	// Create a token
	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Printf("Failed to create token: %v", err)
		return
	}
	fmt.Println("✅ Token created successfully")

	// Validate the token
	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Printf("Failed to validate token: %v", err)
		return
	}
	fmt.Printf("✅ Token validated - User: %s, Role: %s\n", parsedClaims.Username, parsedClaims.Role)

	// Revoke the token
	err = processor.RevokeToken(token)
	if err != nil {
		log.Printf("Failed to revoke token: %v", err)
		return
	}
	fmt.Println("✅ Token revoked successfully")

	// Try to validate the revoked token
	_, valid, err = processor.ValidateToken(token)
	if valid {
		log.Println("❌ Revoked token should not be valid!")
		return
	}
	fmt.Println("✅ Revoked token correctly rejected")

	fmt.Println("🎉 Production setup working perfectly!")
	fmt.Println("   - Rate limiting protects against abuse")
	fmt.Println("   - Blacklist enables token revocation")
	fmt.Println("   - Perfect for production APIs!")
}
