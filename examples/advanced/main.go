// Package main demonstrates operational features: rate limiting, token
// blacklisting, and production configuration.
//
// Error taxonomy, token-type confusion, and rotation patterns live in
// examples/security instead.
//
// Run with: go run ./examples/advanced
package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {
	fmt.Println("JWT Library - Advanced Features")
	fmt.Println("===============================")

	const secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Example 1: Rate limiting
	rateLimitingExample(secretKey)

	fmt.Println()

	// Example 2: Token blacklist and revocation
	blacklistExample(secretKey)

	fmt.Println()

	// Example 3: Production configuration
	productionConfigExample(secretKey)

	fmt.Println("\nAdvanced features example complete!")
}

// rateLimitingExample demonstrates per-subject rate limiting on token creation.
func rateLimitingExample(secretKey string) {
	fmt.Println("Example 1: Rate Limiting")
	fmt.Println("------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.EnableRateLimit = true
	cfg.RateLimitRate = 5             // 5 operations per window
	cfg.RateLimitWindow = time.Minute // per minute, keyed on Subject (or UserID)

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := jwt.Claims{
		UserID:   "user123",
		Username: "rate_test_user",
		Role:     "user",
	}

	// Attempt to create tokens until rate limit is hit
	successCount := 0
	for range 10 {
		_, err := processor.Create(&claims)
		if err != nil {
			if errors.Is(err, jwt.ErrRateLimitExceeded) {
				fmt.Printf("Rate limit exceeded after %d tokens (limit: %d/%v)\n",
					successCount, cfg.RateLimitRate, cfg.RateLimitWindow)
				return
			}
			log.Printf("Unexpected error: %v", err)
			return
		}
		successCount++
	}

	fmt.Printf("Created %d tokens within rate limit\n", successCount)
}

// blacklistExample demonstrates token revocation and the blacklist.
func blacklistExample(secretKey string) {
	fmt.Println("Example 2: Token Blacklist")
	fmt.Println("--------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.Blacklist = jwt.BlacklistConfig{
		MaxSize:         10000,
		CleanupInterval: 5 * time.Minute,
		// EnableAutoCleanup is unnecessary here: the built-in store always
		// cleans up expired entries automatically.
	}

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := jwt.Claims{
		UserID:   "user456",
		Username: "blacklist_test",
		Role:     "user",
	}

	// Create token
	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	// Just-created token: Parse cannot fail here, so only the error is needed
	_, err = processor.Parse(token)
	fmt.Printf("Token valid: %v\n", err == nil)

	// Check revocation status (not revoked yet)
	revoked, _ := processor.IsRevoked(token)
	fmt.Printf("Revoked before: %v\n", revoked)

	// Revoke token
	if err := processor.Revoke(token); err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}

	// Verify revoked token is rejected
	_, err = processor.Parse(token)
	fmt.Printf("Revoked after: %v (rejected: %v)\n", true, errors.Is(err, jwt.ErrTokenRevoked))
}

// productionConfigExample demonstrates a production-ready configuration.
func productionConfigExample(secretKey string) {
	fmt.Println("Example 3: Production Configuration")
	fmt.Println("------------------------------------")

	// Production configuration with all recommended settings
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
		MaxSize:         100000,
		CleanupInterval: 5 * time.Minute,
	}

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create production processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// Verify production configuration works
	claims := jwt.Claims{
		UserID:    "prod_user_001",
		Username:  "production_user",
		Role:      "authenticated",
		SessionID: "prod_session_123",
	}

	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsed, err := processor.Parse(token)
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Printf("Production config verified - User: %s (method=%s, ttl=%v)\n",
		parsed.Username, cfg.SigningMethod, cfg.AccessTokenTTL)
	fmt.Println("\nProduction tips:")
	fmt.Println("  - Load secret key from env: os.Getenv(\"JWT_SECRET_KEY\")")
	fmt.Println("  - Use HTTPS for all token transmission")
	fmt.Println("  - Rotate refresh tokens (see examples/security)")
	fmt.Println("  - Monitor rate limit violations")
}
