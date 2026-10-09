// Package main demonstrates asymmetric signing: RSA (PKCS#1 v1.5 and PSS)
// and ECDSA algorithms, plus public/private key separation.
//
// Use asymmetric signing when you need:
//   - Public/private key separation
//   - Token verification by multiple services without sharing a secret
//   - Enhanced security for distributed systems
//
// Run with: go run ./examples/asymmetric
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

func main() {
	fmt.Println("JWT Library - Asymmetric Signing (RSA/ECDSA)")
	fmt.Println("=============================================")

	// Example 1: RSA signing (PKCS#1 v1.5)
	rsaExample()

	fmt.Println()

	// Example 2: RSA-PSS signing
	psExample()

	fmt.Println()

	// Example 3: ECDSA signing
	ecdsaExample()

	fmt.Println()

	// Example 4: VerificationKey separation
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
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := jwt.Claims{
		UserID:   "rsa_user",
		Username: "alice",
		Role:     "admin",
	}

	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsed, err := processor.Parse(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("RSA token validated - User: %s\n", parsed.Username)
}

func psExample() {
	fmt.Println("Example 2: RSA-PSS Signing (PS256)")
	fmt.Println("-----------------------------------")

	// RSA-PSS is the modern RSA signature scheme; PSS padding has stronger
	// security properties than PKCS#1 v1.5 and is recommended over RS256/384/512.
	// It uses the same *rsa.PrivateKey key type as the RS* methods.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	cfg := jwt.DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = jwt.SigningMethodPS256
	cfg.Issuer = "rsa-pss-service"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := jwt.Claims{
		UserID:   "ps_user",
		Username: "diana",
		Role:     "admin",
	}

	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsed, err := processor.Parse(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("RSA-PSS token validated - User: %s\n", parsed.Username)
}

func ecdsaExample() {
	fmt.Println("Example 3: ECDSA Signing (ES256)")
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
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := jwt.Claims{
		UserID:   "ecdsa_user",
		Username: "bob",
		Role:     "user",
	}

	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsed, err := processor.Parse(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("ECDSA token validated - User: %s\n", parsed.Username)
}

func keySeparationExample() {
	fmt.Println("Example 4: VerificationKey Override")
	fmt.Println("------------------------------------")

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Auth service: creates and signs tokens with the private key
	authCfg := jwt.DefaultConfig()
	authCfg.SigningKey = privateKey
	authCfg.SigningMethod = jwt.SigningMethodRS256
	authCfg.Issuer = "auth-service"

	authProcessor, err := jwt.New(authCfg)
	if err != nil {
		log.Fatalf("Failed to create auth processor: %v", err)
	}
	defer func() { _ = authProcessor.Close() }() // best-effort cleanup

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
	defer func() { _ = apiProcessor.Close() }() // best-effort cleanup

	parsed, err := apiProcessor.Parse(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}
	fmt.Printf("API service verified token (VerificationKey) - User: %s\n", parsed.Username)

	fmt.Println("\nAlgorithm comparison:")
	fmt.Println("  HMAC:    Simple, fast, single-service (HS256/384/512)")
	fmt.Println("  RSA:     Widely supported, larger signatures (RS256/384/512)")
	fmt.Println("  RSA-PSS: Modern RSA padding, recommended over RS* (PS256/384/512)")
	fmt.Println("  ECDSA:   Smaller signatures, faster verification (ES256/384/512)")
}
