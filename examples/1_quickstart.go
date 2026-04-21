//go:build example

package main

import (
	"fmt"
	"log"

	"github.com/cybergodev/jwt"
)

// Quickstart demonstrates the simplest way to use the JWT library.
// Uses the Processor pattern with struct-based configuration.
// Perfect for getting started quickly with minimal setup.
func main() {
	fmt.Println("JWT Library - Quickstart")
	fmt.Println("========================")

	// Step 1: Start with DefaultConfig() for sensible defaults
	// Then customize only what you need (SecretKey is required)
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Step 2: Create processor
	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	fmt.Println("Processor created")

	// Step 3: Create claims with user data
	claims := jwt.Claims{
		UserID:   "user123",
		Username: "john_doe",
		Role:     "user",
	}

	// Step 4: Create access token
	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("\nAccess Token: %s...\n\n", token[:50])
	fmt.Println("Token created successfully")

	// Step 5: Validate token
	parsedClaims, valid, err := processor.Validate(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}
	if !valid {
		log.Fatal("Token is invalid")
	}
	fmt.Printf("Token validated - User: %s, Role: %s\n", parsedClaims.Username, parsedClaims.Role)

	// Step 6: Revoke token (add to blacklist)
	if err := processor.Revoke(token); err != nil {
		log.Printf("Failed to revoke token: %v", err)
	} else {
		fmt.Println("Token revoked successfully")
	}

	// Step 7: Verify revoked token is rejected
	_, valid, _ = processor.Validate(token)
	if !valid {
		fmt.Println("Revoked token correctly rejected")
	}

	fmt.Println("\nQuickstart complete!")
	fmt.Println("\nNext steps:")
	fmt.Println("  - See 2_processor.go for Processor pattern with full configuration")
	fmt.Println("  - See 3_custom_claims.go for custom claim types")
	fmt.Println("  - See 6_web_server.go for production web server example")
}
