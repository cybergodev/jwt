//go:build example

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/cybergodev/jwt"
)

// Asymmetric signing example demonstrates RSA and ECDSA algorithms.
// Use asymmetric signing when you need:
// - Public/private key separation
// - Token verification by multiple services without sharing secret
// - Enhanced security for distributed systems
func main() {
	fmt.Println("JWT Library - Asymmetric Signing (RSA/ECDSA)")
	fmt.Println("=============================================")

	// Example 1: RSA signing
	rsaExample()

	fmt.Println()

	// Example 2: ECDSA signing
	ecdsaExample()

	fmt.Println("\nAsymmetric signing example complete!")
}

func rsaExample() {
	fmt.Println("Example 1: RSA Signing (RS256)")
	fmt.Println("------------------------------")

	// Generate RSA key pair (use 2048+ bits in production)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create processor with RSA private key
	cfg := jwt.DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = jwt.SigningMethodRS256
	cfg.Issuer = "rsa-service"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	fmt.Printf("Processor created with %s\n", cfg.SigningMethod)

	// Create and validate token
	claims := jwt.Claims{
		UserID:   "rsa_user",
		Username: "alice",
		Role:     "admin",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("RSA token created: %s...\n", token[:50])

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("RSA token validated - User: %s\n", parsedClaims.Username)

	fmt.Println("\nDistributed architecture pattern:")
	fmt.Println("  1. Auth service: Holds private key, creates tokens")
	fmt.Println("  2. API services: Share processor instance or use API with same config")
	fmt.Println("  3. Tokens verified against RSA public key embedded in processor")
}

func ecdsaExample() {
	fmt.Println("Example 2: ECDSA Signing (ES256)")
	fmt.Println("--------------------------------")

	// Generate ECDSA key pair (P-256 for ES256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create processor with ECDSA private key
	cfg := jwt.DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = jwt.SigningMethodES256
	cfg.Issuer = "ecdsa-service"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	fmt.Printf("Processor created with %s\n", cfg.SigningMethod)

	// Create and validate token
	claims := jwt.Claims{
		UserID:   "ecdsa_user",
		Username: "bob",
		Role:     "user",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("ECDSA token created: %s...\n", token[:50])

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("ECDSA token validated - User: %s\n", parsedClaims.Username)

	// Algorithm comparison
	fmt.Println("\nAlgorithm comparison:")
	fmt.Println("  HS256: HMAC-SHA256 (symmetric, 32+ byte secret)")
	fmt.Println("  RS256: RSA-SHA256 (asymmetric, 2048+ bit key)")
	fmt.Println("  ES256: ECDSA-SHA256 (asymmetric, P-256 curve)")
	fmt.Println("\nChoose based on your security requirements:")
	fmt.Println("  - HMAC: Simple, fast, single-service authentication")
	fmt.Println("  - RSA:  Widely supported, larger signatures")
	fmt.Println("  - ECDSA: Smaller signatures, faster verification")
}
