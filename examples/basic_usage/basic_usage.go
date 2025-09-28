package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {
	fmt.Println("🚀 JWT Library Usage Examples")
	fmt.Println("================")

	// Basic usage example
	basicExample()
	fmt.Println()

	// Processor mode example
	processorExample()
	fmt.Println()

	// Timezone management example
	timezoneExample()
	fmt.Println()

	// Advanced configuration example
	advancedConfigExample()
}

// Basic usage example - convenience functions
func basicExample() {
	fmt.Println("📝 Basic Usage Example (Convenience Functions)")
	fmt.Println("------------------------")

	// 1. Set strong secret key
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// 2. Create Claims
	claims := jwt.Claims{
		UserID:      "user123",
		Username:    "john_doe",
		Role:        "admin",
		Permissions: []string{"read", "write", "delete"},
		SessionID:   "session_abc123",
		ClientID:    "web_client",
		Extra: map[string]any{
			"department": "engineering",
			"level":      5,
		},
	}

	// 3. Create Token
	token, err := jwt.CreateToken(secretKey, claims)
	if err != nil {
		log.Fatalf("Token creation failed: %v", err)
	}
	fmt.Printf("✅ Token created successfully\n")
	fmt.Printf("Token: %s...\n", token[:50])

	// 4. Validate Token
	parsedClaims, valid, err := jwt.ValidateToken(secretKey, token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	if valid {
		fmt.Printf("✅ Token validation successful\n")
		fmt.Printf("User: %s, Role: %s\n", parsedClaims.Username, parsedClaims.Role)
		fmt.Printf("Permissions: %v\n", parsedClaims.Permissions)
		fmt.Printf("Issued at: %s\n", parsedClaims.IssuedAt.Time.Format("2006-01-02 15:04:05"))
		fmt.Printf("Expires at: %s\n", parsedClaims.ExpiresAt.Time.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("❌ Token is invalid\n")
	}

	// 5. Revoke Token (optional)
	err = jwt.RevokeToken(secretKey, token)
	if err != nil {
		log.Printf("Token revocation failed: %v", err)
	} else {
		fmt.Printf("✅ Token revoked\n")
	}
}

// Processor mode example - advanced usage
func processorExample() {
	fmt.Println("🔧 Processor Mode Example (Advanced Usage)")
	fmt.Println("---------------------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// 1. Create custom configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  30 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "example-app",
		SigningMethod:   jwt.SigningMethodHS256,
	}

	// Basic example doesn't need rate limiting
	config.EnableRateLimit = false

	// 2. Create processor
	processor, err := jwt.NewWithBlacklist(
		secretKey,
		jwt.DefaultBlacklistConfig(),
		config,
	)
	if err != nil {
		log.Fatalf("Processor creation failed: %v", err)
	}
	defer processor.Close() // Ensure resource cleanup

	fmt.Printf("✅ Processor created successfully\n")

	// 3. Create Claims
	claims := jwt.Claims{
		UserID:   "user456",
		Username: "jane_smith",
		Role:     "manager",
		Scopes:   []string{"api:read", "api:write", "admin:users"},
	}

	// 4. Create Token using processor
	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Token creation failed: %v", err)
	}
	fmt.Printf("✅ Token created successfully (TTL: %v)\n", config.AccessTokenTTL)

	// 5. Validate Token
	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	if valid {
		fmt.Printf("✅ Token validation successful\n")
		fmt.Printf("User: %s, Role: %s\n", parsedClaims.Username, parsedClaims.Role)
		fmt.Printf("Scopes: %v\n", parsedClaims.Scopes)
		fmt.Printf("Issuer: %s\n", parsedClaims.Issuer)
	}

	// 6. Revoke Token
	err = processor.RevokeToken(token)
	if err != nil {
		log.Printf("Token revocation failed: %v", err)
	} else {
		fmt.Printf("✅ Token revoked\n")
	}

	// 7. Validate revoked Token
	_, valid, err = processor.ValidateToken(token)
	if err != nil {
		fmt.Printf("✅ Revoked token validation failed (expected behavior): %v\n", err)
	} else if !valid {
		fmt.Printf("✅ Revoked token is invalid (expected behavior)\n")
	}
}

// Timezone management example
func timezoneExample() {
	fmt.Println("🌍 Timezone Management Example")
	fmt.Println("---------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// 1. Get current timezone
	currentTZ := jwt.GetTimezone()
	fmt.Printf("Current timezone: %s\n", currentTZ)

	// 2. Set UTC timezone
	jwt.SetTimezone(time.UTC)
	fmt.Printf("✅ Timezone set to UTC\n")

	// 3. Create Token (using UTC timezone)
	claims := jwt.Claims{
		UserID:   "user789",
		Username: "timezone_user",
	}

	token, err := jwt.CreateToken(secretKey, claims)
	if err != nil {
		log.Fatalf("Token creation failed: %v", err)
	}

	// 4. Validate Token and display times
	parsedClaims, valid, err := jwt.ValidateToken(secretKey, token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	if valid {
		fmt.Printf("✅ Token validation successful\n")
		fmt.Printf("Issued at (UTC): %s\n", parsedClaims.IssuedAt.Time.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("Expires at (UTC): %s\n", parsedClaims.ExpiresAt.Time.Format("2006-01-02 15:04:05 MST"))
	}

	// 5. Restore original timezone
	jwt.SetTimezone(currentTZ)
	fmt.Printf("✅ Timezone restored to: %s\n", currentTZ)
}

// Advanced configuration example
func advancedConfigExample() {
	fmt.Println("⚙️ Advanced Configuration Example")
	fmt.Println("---------------")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// 1. Create advanced configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  15 * time.Minute,    // Short-term access token
		RefreshTokenTTL: 30 * 24 * time.Hour, // 30-day refresh token
		Issuer:          "advanced-example",
		SigningMethod:   jwt.SigningMethodHS512, // Use stronger signing algorithm
	}

	// 2. Create blacklist configuration
	blacklistConfig := jwt.BlacklistConfig{
		CleanupInterval:   2 * time.Minute,
		MaxSize:           50000,
		EnableAutoCleanup: true,
		StoreType:         "memory",
	}

	// Advanced example enables rate limiting
	rateLimitConfig := jwt.RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 50, // Conservative limits
		ValidationRate:    500,
		LoginAttemptRate:  3,
		PasswordResetRate: 1,
		CleanupInterval:   2 * time.Minute,
	}

	config.EnableRateLimit = true
	config.RateLimit = &rateLimitConfig

	// 3. Create processor
	processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Processor creation failed: %v", err)
	}

	fmt.Printf("✅ Advanced processor created successfully\n")
	fmt.Printf("Signing algorithm: %s\n", config.SigningMethod)
	fmt.Printf("Access token TTL: %v\n", config.AccessTokenTTL)
	fmt.Printf("Refresh token TTL: %v\n", config.RefreshTokenTTL)

	// 4. Create complex Claims
	claims := jwt.Claims{
		UserID:      "admin001",
		Username:    "system_admin",
		Role:        "super_admin",
		Permissions: []string{"*"}, // All permissions
		Scopes:      []string{"admin:*", "api:*", "system:*"},
		SessionID:   "admin_session_xyz789",
		ClientID:    "admin_panel",
		Extra: map[string]any{
			"security_level": "maximum",
			"mfa_enabled":    true,
			"last_login":     time.Now().Unix(),
		},
	}

	// 5. Create and validate Token
	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Token creation failed: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	if valid {
		fmt.Printf("✅ Advanced token validation successful\n")
		fmt.Printf("Admin: %s\n", parsedClaims.Username)
		fmt.Printf("Security level: %v\n", parsedClaims.Extra["security_level"])
		fmt.Printf("MFA enabled: %v\n", parsedClaims.Extra["mfa_enabled"])
	}

	// 6. Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = processor.CloseWithContext(ctx)
	if err != nil {
		log.Printf("Processor shutdown failed: %v", err)
	} else {
		fmt.Printf("✅ Processor gracefully closed\n")
	}

	// 7. Clear cache
	jwt.ClearProcessorCache()
	fmt.Printf("✅ Processor cache cleared\n")
}
