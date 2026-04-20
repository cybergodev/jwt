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

	fmt.Println()

	// Example 3: Public/private key separation
	keySeparationExample()

	fmt.Println("\nAsymmetric signing example complete!")
}

func rsaExample() {
	fmt.Println("Example 1: RSA Signing (RS256)")
	fmt.Println("------------------------------")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	cfg := jwt.DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = jwt.SigningMethodRS256
	cfg.Issuer = "rsa-service"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:   "rsa_user",
		Username: "alice",
		Role:     "admin",
	}

	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("RSA token validated - User: %s\n", parsedClaims.Username)
}

func ecdsaExample() {
	fmt.Println("Example 2: ECDSA Signing (ES256)")
	fmt.Println("--------------------------------")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	cfg := jwt.DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = jwt.SigningMethodES256
	cfg.Issuer = "ecdsa-service"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := jwt.Claims{
		UserID:   "ecdsa_user",
		Username: "bob",
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
	fmt.Printf("ECDSA token validated - User: %s\n", parsedClaims.Username)
}

func keySeparationExample() {
	fmt.Println("Example 3: VerificationKey Override")
	fmt.Println("------------------------------------")

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Auth service: creates and signs tokens with private key
	authCfg := jwt.DefaultConfig()
	authCfg.SigningKey = privateKey
	authCfg.SigningMethod = jwt.SigningMethodRS256
	authCfg.Issuer = "auth-service"

	authProcessor, err := jwt.New(authCfg)
	if err != nil {
		log.Fatalf("Failed to create auth processor: %v", err)
	}
	defer authProcessor.Close()

	claims := jwt.Claims{
		UserID:   "distributed_user",
		Username: "charlie",
		Role:     "user",
	}

	token, err := authProcessor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Println("Auth service created token (private key)")

	// API service: uses VerificationKey to explicitly verify with the public key.
	// SigningKey is still required by the current API, but VerificationKey overrides
	// which key is used for verification — useful when the verification key differs
	// from the signing key's embedded public key.
	apiCfg := jwt.DefaultConfig()
	apiCfg.SigningKey = privateKey
	apiCfg.VerificationKey = publicKey
	apiCfg.SigningMethod = jwt.SigningMethodRS256
	apiCfg.Issuer = "auth-service" // Must match token issuer

	apiProcessor, err := jwt.New(apiCfg)
	if err != nil {
		log.Fatalf("Failed to create API processor: %v", err)
	}
	defer apiProcessor.Close()

	parsedClaims, valid, err := apiProcessor.Validate(token)
	if err != nil || !valid {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("API service verified token (VerificationKey) - User: %s\n", parsedClaims.Username)

	fmt.Println("\nAlgorithm comparison:")
	fmt.Println("  HMAC:  Simple, fast, single-service (HS256/384/512)")
	fmt.Println("  RSA:   Widely supported, larger signatures (RS256/384/512)")
	fmt.Println("  ECDSA: Smaller signatures, faster verification (ES256/384/512)")
}
