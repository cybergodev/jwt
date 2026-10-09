package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cybergodev/jwt"
)

// exampleSecret is a strong (>=32 byte, high-entropy) HMAC key shared by the
// examples. Real applications must load secrets from a secret manager rather
// than hard-coding them.
const exampleSecret = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

// Example demonstrates the basic lifecycle: build a config, create a
// Processor, issue a token, and validate it.
func Example() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&jwt.Claims{UserID: "user123", Username: "alice"})
	if err != nil {
		fmt.Println(err)
		return
	}

	claims, valid, err := p.Validate(token)
	if err != nil || !valid {
		fmt.Println("invalid token")
		return
	}

	fmt.Println(claims.UserID)
	// Output: user123
}

// ExampleNew shows how to construct a Processor from DefaultConfig.
func ExampleNew() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	fmt.Println("processor ready")
	// Output: processor ready
}

// ExampleSigningMethod lists a few of the supported signing algorithms.
func ExampleSigningMethod() {
	fmt.Println(jwt.SigningMethodHS256)
	fmt.Println(jwt.SigningMethodRS256)
	// Output:
	// HS256
	// RS256
}

// ExampleNewNumericDate shows how NumericDate marshals to a JSON Unix timestamp.
func ExampleNewNumericDate() {
	nd := jwt.NewNumericDate(time.Unix(1700000000, 0).UTC())
	b, _ := json.Marshal(&nd)
	fmt.Println(string(b))
	// Output: 1700000000
}

// ExampleProcessor_Create creates an access token with the built-in Claims type
// and validates it.
func ExampleProcessor_Create() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&jwt.Claims{UserID: "user123", Username: "alice"})
	if err != nil {
		fmt.Println(err)
		return
	}

	claims, valid, err := p.Validate(token)
	if err != nil || !valid {
		fmt.Println("invalid token")
		return
	}

	fmt.Println(claims.UserID, claims.Username)
	// Output: user123 alice
}

// ExampleProcessor_CreateRefresh demonstrates the refresh-token flow: issue a
// refresh token, then exchange it for a new access token via Refresh.
func ExampleProcessor_CreateRefresh() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	refreshToken, err := p.CreateRefresh(&jwt.Claims{UserID: "user123", Username: "alice"})
	if err != nil {
		fmt.Println(err)
		return
	}

	accessToken, err := p.Refresh(refreshToken)
	if err != nil {
		fmt.Println(err)
		return
	}

	claims, valid, err := p.Validate(accessToken)
	if err != nil || !valid {
		fmt.Println("invalid token")
		return
	}

	fmt.Println(claims.UserID)
	// Output: user123
}

// ExampleProcessor_ValidateInto parses a token into a custom claims type that
// implements CustomClaims.
func ExampleProcessor_ValidateInto() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&exampleClaims{UserID: "user123", Role: "admin"})
	if err != nil {
		fmt.Println(err)
		return
	}

	result, valid, err := p.ValidateInto(token, &exampleClaims{})
	if err != nil || !valid {
		fmt.Println("invalid token")
		return
	}

	parsed := result.(*exampleClaims)
	fmt.Println(parsed.UserID, parsed.Role)
	// Output: user123 admin
}

// ExampleProcessor_Revoke revokes a token and shows that subsequent validation
// fails.
func ExampleProcessor_Revoke() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, _ := p.Create(&jwt.Claims{UserID: "user123", Username: "alice"})

	if err := p.Revoke(token); err != nil {
		fmt.Println(err)
		return
	}

	_, valid, _ := p.Validate(token)
	fmt.Println(valid)
	// Output: false
}

// ExampleProcessor_Refresh demonstrates one-time-use refresh rotation: with
// Config.RotateRefreshTokens the refresh token is revoked as part of the
// refresh, so a replayed refresh token fails with ErrTokenRevoked.
func ExampleProcessor_Refresh() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret
	cfg.RotateRefreshTokens = true

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	refresh, _ := p.CreateRefresh(&jwt.Claims{UserID: "user123", Username: "alice"})

	if _, err := p.Refresh(refresh); err != nil {
		fmt.Println(err)
		return
	}

	// Replaying the same refresh token is rejected.
	_, err = p.Refresh(refresh)
	fmt.Println(errors.Is(err, jwt.ErrTokenRevoked))
	// Output: true
}

// ExampleProcessor_asymmetricSigning signs and validates a token with RSA.
func ExampleProcessor_asymmetricSigning() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}

	cfg := jwt.DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = jwt.SigningMethodRS256

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&jwt.Claims{UserID: "user123", Username: "alice"})
	if err != nil {
		fmt.Println(err)
		return
	}

	claims, valid, err := p.Validate(token)
	if err != nil || !valid {
		fmt.Println("invalid token")
		return
	}

	fmt.Println(claims.Username)
	// Output: alice
}

// ExampleProcessor_Parse verifies a token and extracts its claims. It is the
// error-only replacement for the deprecated Validate.
func ExampleProcessor_Parse() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&jwt.Claims{UserID: "user123", Username: "alice"})
	if err != nil {
		fmt.Println(err)
		return
	}

	claims, err := p.Parse(token)
	if err != nil {
		fmt.Println("invalid token")
		return
	}

	fmt.Println(claims.UserID)
	// Output: user123
}

// ExampleProcessor_ParseInto parses a token into a custom claims type. It is
// the error-only replacement for the deprecated ValidateInto.
func ExampleProcessor_ParseInto() {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = exampleSecret

	p, err := jwt.New(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&exampleClaims{UserID: "user123", Role: "admin"})
	if err != nil {
		fmt.Println(err)
		return
	}

	result, err := p.ParseInto(token, &exampleClaims{})
	if err != nil {
		fmt.Println("invalid token")
		return
	}

	parsed := result.(*exampleClaims)
	fmt.Println(parsed.UserID, parsed.Role)
	// Output: user123 admin
}

// exampleClaims is a custom claims type used by the custom-claims examples.
type exampleClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GetRegisteredClaims implements jwt.CustomClaims.
func (c *exampleClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
	return &c.RegisteredClaims
}

// Validate implements jwt.CustomClaims.
func (c *exampleClaims) Validate() error {
	if c.UserID == "" {
		return errors.New("user_id is required")
	}
	return nil
}
