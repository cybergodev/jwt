// Package main implements the quickstart example: the smallest possible
// create → parse → revoke loop with the jwt library.
//
// Run with: go run ./examples/quickstart
package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/cybergodev/jwt"
)

func main() {
	fmt.Println("JWT Library - Quickstart")
	fmt.Println("========================")

	// Step 1: Start from DefaultConfig() for sensible defaults, then set the
	// fields you need. SecretKey is required for HMAC methods (>= 32 bytes).
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Step 2: Create the processor (always Close it when done)
	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	fmt.Println("Processor created")

	// Step 3: Create claims with user data
	claims := jwt.Claims{
		UserID:   "user123",
		Username: "john_doe",
		Role:     "user",
	}

	// Step 4: Create an access token
	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("\nAccess Token: %s...\n\n", token[:50])

	// Step 5: Parse the token (verifies signature and registered claims).
	// Parse replaces the deprecated Validate: a nil error means the token
	// is valid, so there is no separate boolean to check.
	parsed, err := processor.Parse(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("Token validated - User: %s, Role: %s\n", parsed.Username, parsed.Role)

	// Step 6: Revoke the token (adds its jti to the blacklist)
	if err := processor.Revoke(token); err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}
	fmt.Println("Token revoked")

	// Step 7: The revoked token is now rejected with ErrTokenRevoked
	if _, err := processor.Parse(token); errors.Is(err, jwt.ErrTokenRevoked) {
		fmt.Println("Revoked token correctly rejected")
	}

	fmt.Println("\nQuickstart complete!")
	fmt.Println("\nNext steps:")
	fmt.Println("  - examples/processor      - full configuration surface")
	fmt.Println("  - examples/custom-claims  - custom claim types")
	fmt.Println("  - examples/security       - error handling and rotation")
	fmt.Println("  - examples/web-server     - production web server example")
}
