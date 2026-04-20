//go:build example

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

// Processor pattern demonstrates full control over JWT configuration.
// Recommended for production use where you need custom settings.
func main() {
	fmt.Println("JWT Library - Processor Pattern")
	fmt.Println("===============================")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Example 1: Default configuration
	fmt.Println("\nExample 1: Default Configuration")
	fmt.Println("---------------------------------")
	defaultProcessorExample(secretKey)

	// Example 2: Custom configuration
	fmt.Println("\nExample 2: Custom Configuration")
	fmt.Println("---------------------------------")
	customProcessorExample(secretKey)

	fmt.Println("\nProcessor pattern examples complete!")
}

func defaultProcessorExample(secretKey string) {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:   "user_default",
		Username: "default_user",
		Role:     "user",
	}

	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}

	fmt.Printf("Token validated - User: %s (TTL: %v)\n",
		parsedClaims.Username, cfg.AccessTokenTTL)
}

func customProcessorExample(secretKey string) {
	cfg := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  30 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "my-application-v1",
		SigningMethod:   jwt.SigningMethodHS512,
		Blacklist: jwt.BlacklistConfig{
			MaxSize:           50000,
			CleanupInterval:   10 * time.Minute,
			EnableAutoCleanup: true,
		},
		EnableRateLimit: true,
		RateLimitRate:   50,
		RateLimitWindow: time.Minute,
	}

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:    "user_custom",
		Username:  "custom_user",
		Role:      "admin",
		SessionID: "session_12345",
	}

	// Create access and refresh tokens
	accessToken, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	refreshToken, err := processor.CreateRefresh(&claims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Validate access token
	parsedClaims, valid, err := processor.Validate(accessToken)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("Access token validated - User: %s, Session: %s\n",
		parsedClaims.Username, parsedClaims.SessionID)

	// Refresh access token
	newAccessToken, err := processor.Refresh(refreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	fmt.Println("Access token refreshed")

	// Revoke original access token
	if err := processor.Revoke(accessToken); err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}

	isRevoked, err := processor.IsRevoked(accessToken)
	if err != nil {
		log.Printf("Failed to check revocation: %v", err)
	}
	fmt.Printf("Token revoked: %v\n", isRevoked)

	// Verify revoked token is rejected
	_, valid, _ = processor.Validate(accessToken)
	fmt.Printf("Revoked token rejected: %v\n", !valid)

	// New access token still works
	_, valid, _ = processor.Validate(newAccessToken)
	fmt.Printf("New access token valid: %v\n", valid)
}
