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

func main() {
	fmt.Println("JWT Library - Custom Claims")
	fmt.Println("===========================")

	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.Issuer = "custom-claims-example"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Example 1: Custom claims with Create/ValidateInto
	fmt.Println("\nExample 1: Custom Claims Type")
	fmt.Println("-----------------------------")
	customClaimsExample(processor)

	// Example 2: Built-in Claims with Extra field
	fmt.Println("\nExample 2: Built-in Claims with Extra Field")
	fmt.Println("--------------------------------------------")
	builtInClaimsExample(processor)

	// Example 3: RefreshInto with custom claims
	fmt.Println("\nExample 3: RefreshInto with Custom Claims")
	fmt.Println("------------------------------------------")
	refreshIntoExample(processor)

	// Example 4: Custom validation error
	fmt.Println("\nExample 4: Custom Validation")
	fmt.Println("-----------------------------")
	customValidationExample(processor)

	fmt.Println("\nCustom claims example complete!")
}

func customClaimsExample(processor *jwt.Processor) {
	customClaims := &AppClaims{
		UserID: "user789",
		TeamID: "team-abc",
		Roles:  []string{"developer", "reviewer"},
	}

	// Create token with custom claims
	token, err := processor.Create(customClaims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Println("Token created with custom claims")

	// Validate and parse into custom claims using ValidateInto
	resultClaims := &AppClaims{}
	result, valid, err := processor.ValidateInto(token, resultClaims)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}

	parsed := result.(*AppClaims)
	fmt.Printf("Token validated:\n")
	fmt.Printf("  UserID: %s, TeamID: %s\n", parsed.UserID, parsed.TeamID)
	fmt.Printf("  Roles: %v, Issuer: %s\n", parsed.Roles, parsed.Issuer)
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

	token, err := processor.Create(&claims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Printf("Built-in claims validated: UserID=%s, Username=%s\n",
		parsedClaims.UserID, parsedClaims.Username)
	if teamID, ok := parsedClaims.Extra["team_id"].(string); ok {
		fmt.Printf("  Extra - TeamID: %s, Level: %s\n",
			teamID, parsedClaims.Extra["level"])
	}
}

func refreshIntoExample(processor *jwt.Processor) {
	// RefreshInto: refresh a custom-claims token into a new access token
	claims := &AppClaims{
		UserID: "user999",
		TeamID: "team-refresh",
		Roles:  []string{"admin"},
	}

	// Create refresh token with custom claims
	refreshToken, err := processor.CreateRefresh(claims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	fmt.Println("Refresh token created")

	// RefreshInto parses the refresh token and creates a new access token
	// The custom claims struct is populated with the parsed data
	parsedClaims := &AppClaims{}
	newAccessToken, err := processor.RefreshInto(refreshToken, parsedClaims)
	if err != nil {
		log.Fatalf("Failed to refresh into: %v", err)
	}
	fmt.Printf("Token refreshed - UserID: %s, TeamID: %s\n",
		parsedClaims.UserID, parsedClaims.TeamID)

	// Validate the new access token with ValidateInto
	resultClaims := &AppClaims{}
	_, valid, err := processor.ValidateInto(newAccessToken, resultClaims)
	if err != nil || !valid {
		log.Fatalf("Failed to validate refreshed token: %v", err)
	}
	fmt.Printf("Refreshed token validated - UserID: %s\n", resultClaims.UserID)
}

func customValidationExample(processor *jwt.Processor) {
	// Demonstrates validation error handling with custom claims
	invalidClaims := &AppClaims{
		UserID: "", // Missing required field
		TeamID: "team-abc",
	}

	_, err := processor.Create(invalidClaims)
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidClaims) {
			fmt.Printf("Validation correctly rejected: %v\n", err)
		}
	}

	// Parse without verification (for debugging/inspection)
	validClaims := &AppClaims{UserID: "user888", TeamID: "team-debug"}
	refreshToken, err := processor.CreateRefresh(validClaims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	var parsed AppClaims
	if err := processor.ParseUnverified(refreshToken, &parsed); err != nil {
		log.Fatalf("Failed to parse token: %v", err)
	}
	fmt.Printf("Unverified parse - UserID: %s, ExpiresAt: %v\n",
		parsed.UserID, parsed.ExpiresAt.Time.Format(time.RFC3339))
}
