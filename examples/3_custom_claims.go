//go:build example

package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

// AppClaims demonstrates custom claims with application-specific fields.
// It embeds jwt.RegisteredClaims and implements jwt.CustomClaims interface.
type AppClaims struct {
	UserID string   `json:"user_id"`
	TeamID string   `json:"team_id"`
	Roles  []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// GetRegisteredClaims implements jwt.CustomClaims interface.
func (c *AppClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
	return &c.RegisteredClaims
}

// Validate implements jwt.CustomClaims interface.
func (c *AppClaims) Validate() error {
	if c.UserID == "" {
		return errors.New("user_id is required")
	}
	if c.TeamID == "" {
		return errors.New("team_id is required")
	}
	return nil
}

// Custom claims example demonstrates using custom claim types
// with the CreateTokenWith and ValidateTokenWith methods.
func main() {
	fmt.Println("JWT Library - Custom Claims")
	fmt.Println("===========================")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Create processor
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.Issuer = "custom-claims-example"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Example 1: Custom claims with CreateTokenWith
	fmt.Println("\nExample 1: Custom Claims Type")
	fmt.Println("-----------------------------")
	customClaimsExample(processor)

	// Example 2: Built-in Claims with Extra field
	fmt.Println("\nExample 2: Built-in Claims with Extra Field")
	fmt.Println("--------------------------------------------")
	builtInClaimsExample(processor)

	// Example 3: Custom validation error
	fmt.Println("\nExample 3: Custom Validation")
	fmt.Println("-----------------------------")
	customValidationExample(processor)

	fmt.Println("\nCustom claims example complete!")
}

func customClaimsExample(processor *jwt.Processor) {
	// Create custom claims
	customClaims := &AppClaims{
		UserID: "user789",
		TeamID: "team-abc",
		Roles:  []string{"developer", "reviewer"},
	}

	// Create token with custom claims using CreateTokenWith
	token, err := processor.CreateTokenWith(customClaims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Printf("Token created with custom claims\n")

	// Validate and parse into custom claims using ValidateTokenWith
	resultClaims := &AppClaims{}
	result, valid, err := processor.ValidateTokenWith(token, resultClaims)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}

	parsed := result.(*AppClaims)
	fmt.Printf("Token validated:\n")
	fmt.Printf("  UserID: %s\n", parsed.UserID)
	fmt.Printf("  TeamID: %s\n", parsed.TeamID)
	fmt.Printf("  Roles: %v\n", parsed.Roles)
	fmt.Printf("  Issuer: %s\n", parsed.Issuer)
}

func builtInClaimsExample(processor *jwt.Processor) {
	// Use built-in Claims type with Extra field for additional data
	claims := jwt.Claims{
		UserID:   "user456",
		Username: "developer",
		Role:     "team_member",
		Extra: map[string]any{
			"team_id":    "team-xyz",
			"level":      "senior",
			"department": "engineering",
		},
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Printf("Built-in claims validated:\n")
	fmt.Printf("  UserID: %s\n", parsedClaims.UserID)
	fmt.Printf("  Username: %s\n", parsedClaims.Username)
	if teamID, ok := parsedClaims.Extra["team_id"].(string); ok {
		fmt.Printf("  TeamID (Extra): %s\n", teamID)
	}
	if level, ok := parsedClaims.Extra["level"].(string); ok {
		fmt.Printf("  Level (Extra): %s\n", level)
	}
}

func customValidationExample(processor *jwt.Processor) {
	// Test validation error handling
	invalidClaims := &AppClaims{
		UserID: "", // Missing required field
		TeamID: "team-abc",
	}

	_, err := processor.CreateTokenWith(invalidClaims)
	if err != nil {
		fmt.Printf("Validation correctly failed:\n")
		fmt.Printf("  Error: %v\n", err)

		// Check if it's a claims validation error
		if errors.Is(err, jwt.ErrInvalidClaims) {
			fmt.Printf("  Type: Invalid claims error\n")
		}
	}

	// Also test refresh token with custom claims
	fmt.Println("\nRefresh token with custom claims:")
	validClaims := &AppClaims{
		UserID: "user999",
		TeamID: "team-refresh",
		Roles:  []string{"admin"},
	}

	refreshToken, err := processor.CreateRefreshTokenWith(validClaims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	fmt.Printf("Refresh token created\n")

	// Parse without verification (for debugging/inspection)
	var parsedRefresh AppClaims
	err = processor.ParseUnverified(refreshToken, &parsedRefresh)
	if err != nil {
		log.Fatalf("Failed to parse token: %v", err)
	}
	fmt.Printf("Refresh token parsed (unverified):\n")
	fmt.Printf("  UserID: %s\n", parsedRefresh.UserID)
	fmt.Printf("  ExpiresAt: %v\n", parsedRefresh.ExpiresAt.Time.Format(time.RFC3339))
}
