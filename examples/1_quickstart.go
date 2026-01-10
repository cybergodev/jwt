package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

// Quickstart demonstrates the simplest way to use the JWT library
// Perfect for getting started quickly with minimal configuration
func main() {
	fmt.Println("🚀 JWT Library - Quickstart Guide")
	fmt.Println("==================================\n ")

	// Use a strong secret key (minimum 32 bytes)
	// In production, load from environment variable: os.Getenv("JWT_SECRET_KEY")
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Example 1: Convenience API (simplest approach)
	convenienceAPIExample(secretKey)
	fmt.Println()

	// Example 2: Processor API (recommended for production)
	processorAPIExample(secretKey)
}

// convenienceAPIExample demonstrates the simplest way to create and validate tokens
// Best for: Quick prototyping, simple applications, learning
func convenienceAPIExample(secretKey string) {
	fmt.Println("📝 Example 1: Convenience API (Simplest)")
	fmt.Println("-----------------------------------------")

	// Step 1: Create claims with user information
	claims := jwt.Claims{
		UserID:      "user123",
		Username:    "john_doe",
		Role:        "user",
		Permissions: []string{"read", "write"},
	}

	// Step 2: Create token (one line!)
	token, err := jwt.CreateToken(secretKey, claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("✅ Token created: %s...\n", token[:50])

	// Step 3: Validate token (one line!)
	parsedClaims, valid, err := jwt.ValidateToken(secretKey, token)
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}

	if valid {
		fmt.Printf("✅ Token is valid\n")
		fmt.Printf("   User: %s, Role: %s\n", parsedClaims.Username, parsedClaims.Role)
		fmt.Printf("   Expires: %s\n", parsedClaims.ExpiresAt.Time.Format("2006-01-02 15:04:05"))
	}

	// Step 4: Revoke token (optional)
	err = jwt.RevokeToken(secretKey, token)
	if err != nil {
		log.Printf("Failed to revoke token: %v", err)
	} else {
		fmt.Printf("✅ Token revoked\n")
	}

	// Step 5: Verify revoked token is rejected
	_, valid, _ = jwt.ValidateToken(secretKey, token)
	if !valid {
		fmt.Printf("✅ Revoked token correctly rejected\n")
	}
}

// processorAPIExample demonstrates the recommended approach for production applications
// Best for: Production apps, custom configuration, resource management
func processorAPIExample(secretKey string) {
	fmt.Println("🔧 Example 2: Processor API (Recommended)")
	fmt.Println("------------------------------------------")

	// Step 1: Create custom configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  15 * time.Minute,   // Short-lived access tokens
		RefreshTokenTTL: 7 * 24 * time.Hour, // Weekly refresh
		Issuer:          "my-app",
		SigningMethod:   jwt.SigningMethodHS256,
		EnableRateLimit: false, // Disable for this simple example
	}

	// Step 2: Create processor with blacklist support
	processor, err := jwt.NewWithBlacklist(
		secretKey,
		jwt.DefaultBlacklistConfig(),
		config,
	)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close() // Always close to free resources

	fmt.Printf("✅ Processor created with custom config\n")

	// Step 3: Create claims
	claims := jwt.Claims{
		UserID:   "user456",
		Username: "jane_smith",
		Role:     "admin",
		Scopes:   []string{"api:read", "api:write", "admin:users"},
	}

	// Step 4: Create access token
	accessToken, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("✅ Access token created (TTL: %v)\n", config.AccessTokenTTL)

	// Step 5: Create refresh token
	refreshToken, err := processor.CreateRefreshToken(claims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	fmt.Printf("✅ Refresh token created (TTL: %v)\n", config.RefreshTokenTTL)

	// Step 6: Validate access token
	parsedClaims, valid, err := processor.ValidateToken(accessToken)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}
	fmt.Printf("✅ Token validated\n")
	fmt.Printf("   User: %s, Role: %s\n", parsedClaims.Username, parsedClaims.Role)
	fmt.Printf("   Scopes: %v\n", parsedClaims.Scopes)

	// Step 7: Use refresh token to get new access token
	newAccessToken, err := processor.RefreshToken(refreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	fmt.Printf("✅ New access token generated from refresh token\n")

	// Step 8: Revoke refresh token
	err = processor.RevokeToken(refreshToken)
	if err != nil {
		log.Printf("Failed to revoke token: %v", err)
	} else {
		fmt.Printf("✅ Refresh token revoked\n")
	}

	// Step 9: Verify new access token still works
	_, valid, err = processor.ValidateToken(newAccessToken)
	if valid && err == nil {
		fmt.Printf("✅ New access token still valid after refresh token revocation\n")
	}

	fmt.Println("\n🎉 Quickstart complete! Check other examples for advanced features.")
}
