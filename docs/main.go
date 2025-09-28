package main

import (
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {

	// Define user claims
	// claims := jwt.Claims{
	// 	UserID:      "user_12345",
	// 	Username:    "john.doe",
	// 	Role:        "admin",
	// 	Permissions: []string{"read", "write", "delete"},
	// }

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-g!"

	// // Set token expiration time (default 15 minutes) - when token expires
	// claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Minute))
	//
	// // Create token (processor automatically cached)
	//
	// token, err := jwt.CreateToken(secretKey, claims)
	// if err != nil {
	// 	log.Panicf("token creation failed: %v", err)
	// }
	//
	// fmt.Printf("Generated token: %s\n", token)

	// Custom configuration for production
	// config := jwt.Config{
	// 	AccessTokenTTL:  10 * time.Minute,       // Short-lived tokens
	// 	RefreshTokenTTL: 24 * time.Hour,         // Daily refresh
	// 	Issuer:          "myapp-production",     // App identifier
	// 	SigningMethod:   jwt.SigningMethodHS512, // Stronger algorithm
	// }
	//
	// processor, err := jwt.New(secretKey, config)
	// if err != nil {
	// 	log.Fatalf("Processor creation failed: %v", err)
	// }
	// defer processor.Close()
	//
	// token, err := processor.CreateToken(claims)
	// fmt.Println(token)

	// High-performance blacklist for production
	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           100000,          // 100K revoked tokens
		CleanupInterval:   5 * time.Minute, // Regular cleanup
		EnableAutoCleanup: true,            // Automatic maintenance
		StoreType:         "memory",        // Fast in-memory storage
	}

	config := jwt.Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "secure-app-v2",
	}

	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Secure processor creation failed: %v", err)
	}
	defer processor.Close()

}
