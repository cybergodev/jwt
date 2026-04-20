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

	claims := jwt.Claims{
		UserID:   "user123",
		Username: "rate_test_user",
		Role:     "user",
	}

	// Attempt to create tokens until rate limit is hit
	successCount := 0
	for i := 0; i < 10; i++ {
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

	claims := jwt.Claims{
		UserID:   "user456",
		Username: "blacklist_test",
		Role:     "user",
	}

	// Create and validate token
	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	_, valid, _ := processor.Validate(token)
	fmt.Printf("Token valid: %v\n", valid)

	// Check revocation status (not revoked yet)
	revoked, _ := processor.IsRevoked(token)
	fmt.Printf("Revoked before: %v\n", revoked)

	// Revoke token
	if err := processor.Revoke(token); err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}

	// Verify revoked token is rejected
	_, valid, _ = processor.Validate(token)
	fmt.Printf("Revoked after: %v (token rejected: %v)\n", true, !valid)
}

// errorHandlingExample demonstrates proper error handling.
func errorHandlingExample(secretKey string) {
	fmt.Println("Example 3: Error Handling")
	fmt.Println("-------------------------")

	cfg := jwt.Config{SecretKey: secretKey}
	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Invalid secret key (too short)
	_, err = jwt.New(jwt.Config{SecretKey: "too-short"})
	if errors.Is(err, jwt.ErrInvalidSecretKey) {
		fmt.Println("Caught: invalid secret key")
	}

	// Invalid token format
	_, _, err = processor.Validate("invalid.token.format")
	if errors.Is(err, jwt.ErrInvalidToken) {
		fmt.Println("Caught: invalid token format")
	}

	// Empty claims validation
	_, err = processor.Create(&jwt.Claims{})
	if errors.Is(err, jwt.ErrInvalidClaims) {
		fmt.Println("Caught: empty claims")
	}

	// Demonstrate error type switching
	token, _ := processor.Create(&jwt.Claims{UserID: "test"})
	_, valid, validateErr := processor.Validate(token)
	if !valid || validateErr != nil {
		switch {
		case errors.Is(validateErr, jwt.ErrTokenExpired):
			fmt.Println("Token expired")
		case errors.Is(validateErr, jwt.ErrTokenRevoked):
			fmt.Println("Token revoked")
		case errors.Is(validateErr, jwt.ErrTokenInvalidIssuer):
			fmt.Println("Invalid issuer")
		default:
			fmt.Printf("Other error: %v\n", validateErr)
		}
	} else {
		fmt.Println("Error handling tests passed")
	}
}

// productionConfigExample demonstrates production-ready configuration.
func productionConfigExample(secretKey string) {
	fmt.Println("Example 4: Production Configuration")
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
		MaxSize:           100000,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
	}

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create production processor: %v", err)
	}
	defer processor.Close()

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

	parsedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Printf("Production config verified - User: %s (method=%s, ttl=%v)\n",
		parsedClaims.Username, cfg.SigningMethod, cfg.AccessTokenTTL)
	fmt.Println("\nProduction tips:")
	fmt.Println("  - Load secret key from env: os.Getenv(\"JWT_SECRET_KEY\")")
	fmt.Println("  - Use HTTPS for all token transmission")
	fmt.Println("  - Implement token refresh workflow")
	fmt.Println("  - Monitor rate limit violations")
}
