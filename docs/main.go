package main

import (
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-g!"

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
