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
	// Create processor with default configuration
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	fmt.Printf("Processor created with default settings:\n")
	fmt.Printf("  - Access Token TTL: %v\n", cfg.AccessTokenTTL)
	fmt.Printf("  - Refresh Token TTL: %v\n", cfg.RefreshTokenTTL)
	fmt.Printf("  - Signing Method: %s\n", cfg.SigningMethod)

	// Create token
	claims := jwt.Claims{
		UserID:   "user_default",
		Username: "default_user",
		Role:     "user",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}

	fmt.Printf("Token validated - User: %s\n", parsedClaims.Username)
}

func customProcessorExample(secretKey string) {
	// Create processor with custom configuration
	cfg := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  30 * time.Minute,       // Custom access token TTL
		RefreshTokenTTL: 24 * time.Hour,         // Custom refresh token TTL
		Issuer:          "my-application-v1",    // Custom issuer
		SigningMethod:   jwt.SigningMethodHS512, // Stronger algorithm
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

	fmt.Printf("Processor created with custom settings:\n")
	fmt.Printf("  - Access Token TTL: %v\n", cfg.AccessTokenTTL)
	fmt.Printf("  - Refresh Token TTL: %v\n", cfg.RefreshTokenTTL)
	fmt.Printf("  - Issuer: %s\n", cfg.Issuer)
	fmt.Printf("  - Signing Method: %s\n", cfg.SigningMethod)
	fmt.Printf("  - Rate Limiting: %v (%d/%v)\n", cfg.EnableRateLimit, cfg.RateLimitRate, cfg.RateLimitWindow)

	// Create access and refresh tokens
	claims := jwt.Claims{
		UserID:    "user_custom",
		Username:  "custom_user",
		Role:      "admin",
		SessionID: "session_12345",
	}

	// Create access token
	accessToken, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}
	fmt.Printf("Access token created\n")

	// Create refresh token
	refreshToken, err := processor.CreateRefreshToken(claims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	fmt.Printf("Refresh token created\n")

	// Validate access token
	parsedClaims, valid, err := processor.ValidateToken(accessToken)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("Access token validated - User: %s, Session: %s\n",
		parsedClaims.Username, parsedClaims.SessionID)

	// Refresh access token
	newAccessToken, err := processor.RefreshToken(refreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	fmt.Printf("Access token refreshed\n")

	// Revoke original access token
	if err := processor.RevokeToken(accessToken); err != nil {
		log.Printf("Failed to revoke token: %v", err)
	} else {
		fmt.Printf("Access token revoked\n")
	}

	// Check revocation status
	isRevoked, err := processor.IsTokenRevoked(accessToken)
	if err != nil {
		log.Printf("Failed to check revocation: %v", err)
	} else {
		fmt.Printf("Token revoked status: %v\n", isRevoked)
	}

	// Verify revoked token is rejected
	_, valid, _ = processor.ValidateToken(accessToken)
	if !valid {
		fmt.Printf("Revoked token correctly rejected\n")
	}

	// New access token still works
	_, valid, _ = processor.ValidateToken(newAccessToken)
	if valid {
		fmt.Printf("New access token is valid\n")
	}
}
