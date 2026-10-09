// Package main demonstrates custom claims types implementing
// jwt.CustomClaims, plus the built-in Claims type with its Extra field.
//
// Run with: go run ./examples/custom-claims
package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cybergodev/jwt"
)

// AppClaims demonstrates custom claims with application-specific fields.
// It embeds jwt.RegisteredClaims and implements jwt.CustomClaims.
type AppClaims struct {
	UserID string   `json:"user_id"`
	TeamID string   `json:"team_id"`
	Roles  []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// GetRegisteredClaims implements jwt.CustomClaims.
func (c *AppClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
	return &c.RegisteredClaims
}

// Validate implements jwt.CustomClaims. Called after standard JWT validation
// (signature, exp, nbf, iss, aud, blacklist) passes.
func (c *AppClaims) Validate() error {
	if c.UserID == "" {
		return errors.New("user_id is required")
	}
	if c.TeamID == "" {
		return errors.New("team_id is required")
	}
	return nil
}

// RateLimitKey implements the optional jwt.RateLimitKeyer interface. Without
// it, token creation for claims with an empty Subject skips rate limiting;
// with it, the processor rate-limits on UserID.
func (c *AppClaims) RateLimitKey() string {
	return c.UserID
}

func main() {
	fmt.Println("JWT Library - Custom Claims")
	fmt.Println("===========================")

	const secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.Issuer = "custom-claims-example"

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// Example 1: Custom claims type with Create/ParseInto
	fmt.Println("\nExample 1: Custom Claims Type")
	fmt.Println("-----------------------------")
	customClaimsExample(processor)

	// Example 2: Built-in Claims with the Extra field
	fmt.Println("\nExample 2: Built-in Claims with Extra Field")
	fmt.Println("--------------------------------------------")
	builtInClaimsExample(processor)

	// Example 3: RefreshInto with custom claims
	fmt.Println("\nExample 3: RefreshInto with Custom Claims")
	fmt.Println("------------------------------------------")
	refreshIntoExample(processor)

	// Example 4: Custom validation and unverified parsing
	fmt.Println("\nExample 4: Custom Validation")
	fmt.Println("-----------------------------")
	customValidationExample(processor)

	// Example 5: RateLimitKeyer
	fmt.Println("\nExample 5: Rate Limiting Custom Claims")
	fmt.Println("---------------------------------------")
	rateLimitKeyExample(secretKey)

	fmt.Println("\nCustom claims example complete!")
}

func customClaimsExample(processor *jwt.Processor) {
	customClaims := &AppClaims{
		UserID: "user789",
		TeamID: "team-abc",
		Roles:  []string{"developer", "reviewer"},
	}

	token, err := processor.Create(customClaims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	fmt.Println("Token created with custom claims")

	// ParseInto verifies the token and populates the provided struct in
	// place. It replaces the deprecated ValidateInto.
	parsed := &AppClaims{}
	if _, err := processor.ParseInto(token, parsed); err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Println("Token validated:")
	fmt.Printf("  UserID: %s, TeamID: %s\n", parsed.UserID, parsed.TeamID)
	fmt.Printf("  Roles: %v, Issuer: %s\n", parsed.Roles, parsed.Issuer)
}

func builtInClaimsExample(processor *jwt.Processor) {
	// Use the built-in Claims type with Extra for arbitrary additional fields
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

	parsed, err := processor.Parse(token)
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}

	fmt.Printf("Built-in claims validated: UserID=%s, Username=%s\n",
		parsed.UserID, parsed.Username)
	if teamID, ok := parsed.Extra["team_id"].(string); ok {
		fmt.Printf("  Extra - TeamID: %s, Level: %s\n",
			teamID, parsed.Extra["level"])
	}
}

func refreshIntoExample(processor *jwt.Processor) {
	// RefreshInto parses a refresh token, populates the custom claims struct
	// with the parsed data, and returns a new access token
	claims := &AppClaims{
		UserID: "user999",
		TeamID: "team-refresh",
		Roles:  []string{"admin"},
	}

	refreshToken, err := processor.CreateRefresh(claims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	fmt.Println("Refresh token created")

	parsedClaims := &AppClaims{}
	newAccessToken, err := processor.RefreshInto(refreshToken, parsedClaims)
	if err != nil {
		log.Fatalf("Failed to refresh into: %v", err)
	}
	fmt.Printf("Token refreshed - UserID: %s, TeamID: %s\n",
		parsedClaims.UserID, parsedClaims.TeamID)

	// Validate the new access token
	resultClaims := &AppClaims{}
	if _, err := processor.ParseInto(newAccessToken, resultClaims); err != nil {
		log.Fatalf("Failed to validate refreshed token: %v", err)
	}
	fmt.Printf("Refreshed token validated - UserID: %s\n", resultClaims.UserID)
}

func customValidationExample(processor *jwt.Processor) {
	// AppClaims.Validate runs on both Create and ParseInto; missing required
	// fields surface as ErrInvalidClaims
	invalidClaims := &AppClaims{
		UserID: "", // Missing required field
		TeamID: "team-abc",
	}

	if _, err := processor.Create(invalidClaims); errors.Is(err, jwt.ErrInvalidClaims) {
		fmt.Printf("Validation correctly rejected: %v\n", err)
	}

	// Parse without verification (for debugging/inspection only — never trust
	// the result for authorization decisions)
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
		parsed.UserID, parsed.ExpiresAt.Format(time.RFC3339))
}

func rateLimitKeyExample(secretKey string) {
	// Custom claims types have an empty Subject claim, so without RateLimitKeyer
	// their token creation would not be rate-limited at all.
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.EnableRateLimit = true
	cfg.RateLimitRate = 2             // 2 tokens per...
	cfg.RateLimitWindow = time.Minute // ...per minute, keyed by RateLimitKey()

	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	for i := 1; i <= 3; i++ {
		_, err := processor.Create(&AppClaims{UserID: "limited-user", TeamID: "team-rl"})
		switch {
		case err == nil:
			fmt.Printf("Create #%d: allowed\n", i)
		case errors.Is(err, jwt.ErrRateLimitExceeded):
			fmt.Printf("Create #%d: rejected (rate limit keyed on UserID)\n", i)
		default:
			log.Fatalf("Unexpected error: %v", err)
		}
	}
}
