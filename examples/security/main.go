// Package main demonstrates security-relevant patterns:
//   - Configuration validation (fail fast at construction)
//   - Tampered signatures and algorithm-confusion detection
//   - Structured validation errors (errors.As with jwt.ValidationError)
//   - Token type confusion in both directions (access ↔ refresh)
//   - One-time-use refresh token rotation
//   - RequireExpiration for tokens from other issuers
//
// Every failure below maps to a sentinel error; match with errors.Is:
//
//	jwt.ErrInvalidSecretKey     ErrInvalidConfig      ErrInvalidClaims
//	jwt.ErrInvalidToken         ErrAlgorithmMismatch  ErrTokenExpired
//	jwt.ErrTokenRevoked         ErrTokenInvalidIssuer ErrTokenInvalidAudience
//	jwt.ErrTokenTypeMismatch    ErrExpirationRequired
//
// Run with: go run ./examples/security
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cybergodev/jwt"
)

const secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

func main() {
	fmt.Println("JWT Library - Security Patterns")
	fmt.Println("================================")

	configValidationExample()
	tamperExample()
	algorithmConfusionExample()
	structuredErrorExample()
	typeConfusionExample()
	refreshRotationExample()
	requireExpirationExample()

	fmt.Println("\nSecurity patterns example complete!")
}

// configValidationExample shows that New validates its configuration, so bad
// keys fail at startup instead of at the first token operation.
func configValidationExample() {
	fmt.Println("\nExample 1: Configuration Validation")
	fmt.Println("------------------------------------")

	_, err := jwt.New(jwt.Config{SecretKey: "too-short"})
	fmt.Printf("Short secret key rejected:  %v\n", errors.Is(err, jwt.ErrInvalidSecretKey))

	_, err = jwt.New(jwt.Config{SecretKey: secretKey, SigningMethod: jwt.SigningMethod("HS128")})
	fmt.Printf("Unknown signing method:    %v\n", errors.Is(err, jwt.ErrInvalidSigningMethod))
}

// tamperExample corrupts a token's signature: the payload parses, but the
// MAC no longer matches, so the token is rejected with ErrInvalidToken.
func tamperExample() {
	fmt.Println("\nExample 2: Tampered Signature")
	fmt.Println("-----------------------------")

	p := newDefaultProcessor()
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&jwt.Claims{UserID: "victim", Username: "victim"})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	// Flip the last character of the signature part
	sub := "A"
	if token[len(token)-1] == 'A' {
		sub = "B"
	}
	tampered := token[:len(token)-1] + sub

	_, err = p.Parse(tampered)
	fmt.Printf("Tampered token rejected:   %v\n", errors.Is(err, jwt.ErrInvalidToken))
}

// algorithmConfusionExample shows detection of algorithm-confusion attacks
// (OWASP A07): a token signed with a different algorithm than the one
// configured — even with the correct key material — is rejected with
// ErrAlgorithmMismatch rather than silently accepted.
func algorithmConfusionExample() {
	fmt.Println("\nExample 3: Algorithm Confusion")
	fmt.Println("------------------------------")

	// Attacker-side processor: same secret, but signs with HS384
	attackerCfg := jwt.DefaultConfig()
	attackerCfg.SecretKey = secretKey
	attackerCfg.SigningMethod = jwt.SigningMethodHS384
	attacker := mustNew(attackerCfg)
	defer func() { _ = attacker.Close() }() // best-effort cleanup

	forged, err := attacker.Create(&jwt.Claims{UserID: "attacker", Username: "attacker"})
	if err != nil {
		log.Fatalf("Failed to create forged token: %v", err)
	}

	// Defender-side processor expects HS256
	defender := newDefaultProcessor()
	defer func() { _ = defender.Close() }() // best-effort cleanup

	_, err = defender.Parse(forged)
	fmt.Printf("HS384 token vs HS256 config rejected: %v\n",
		errors.Is(err, jwt.ErrAlgorithmMismatch))
}

// structuredErrorExample extracts field-level detail from validation failures
// with errors.As and jwt.ValidationError.
func structuredErrorExample() {
	fmt.Println("\nExample 4: Structured Validation Errors")
	fmt.Println("---------------------------------------")

	p := newDefaultProcessor()
	defer func() { _ = p.Close() }() // best-effort cleanup

	// UserID longer than the 256-byte limit
	_, err := p.Create(&jwt.Claims{
		UserID:   strings.Repeat("x", 257),
		Username: "long-user",
	})
	fmt.Printf("Create failed: %v\n", err)

	var valErr *jwt.ValidationError
	if errors.As(err, &valErr) {
		fmt.Printf("  Field: %q, Message: %q\n", valErr.Field, valErr.Message)
	}
	fmt.Printf("  Still matches sentinel: errors.Is(err, ErrInvalidClaims)=%v\n",
		errors.Is(err, jwt.ErrInvalidClaims))
}

// typeConfusionExample shows that refresh tokens cannot serve as access
// tokens (opt-in via RejectRefreshAsAccess) and access tokens cannot be
// refreshed — both fail with ErrTokenTypeMismatch.
func typeConfusionExample() {
	fmt.Println("\nExample 5: Token Type Confusion")
	fmt.Println("--------------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	// Without this flag a refresh token (7-day TTL by default) would pass
	// Parse for its full lifetime and could serve as an access credential.
	cfg.RejectRefreshAsAccess = true
	p := mustNew(cfg)
	defer func() { _ = p.Close() }() // best-effort cleanup

	claims := &jwt.Claims{UserID: "confused", Username: "confused"}

	refreshToken, err := p.CreateRefresh(claims)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Refresh token presented as an access token -> rejected (opt-in)
	_, err = p.Parse(refreshToken)
	fmt.Printf("Refresh token as access rejected: %v\n",
		errors.Is(err, jwt.ErrTokenTypeMismatch))

	// Access token presented to Refresh -> rejected (always, by default)
	accessToken, err := p.Create(claims)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}
	_, err = p.Refresh(accessToken)
	fmt.Printf("Access token as refresh rejected: %v\n",
		errors.Is(err, jwt.ErrTokenTypeMismatch))
}

// refreshRotationExample implements one-time-use refresh semantics. Refresh
// does NOT revoke the supplied token by default; revoke it explicitly to
// prevent replay of a stolen refresh token.
func refreshRotationExample() {
	fmt.Println("\nExample 6: One-Time-Use Refresh Rotation")
	fmt.Println("-----------------------------------------")

	// Built-in rotation: Refresh revokes the old refresh token (by its jti)
	// before minting the new one — fail-closed, so an accepted refresh token
	// can never be replayed. No separate Revoke call needed.
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.RotateRefreshTokens = true
	p, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	refreshToken, err := p.CreateRefresh(&jwt.Claims{UserID: "rotating", Username: "rotating"})
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// First use: succeeds and retires the refresh token in the same call
	if _, err := p.Refresh(refreshToken); err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	fmt.Println("First refresh:             succeeded")

	// Replay attempt: the rotated refresh token no longer works
	_, err = p.Refresh(refreshToken)
	fmt.Printf("Replayed refresh rejected: %v\n", errors.Is(err, jwt.ErrTokenRevoked))
}

// requireExpirationExample validates a token from another issuer that lacks
// an exp claim. RFC 7519 makes exp optional, so by default such a token never
// expires; RequireExpiration rejects it with ErrExpirationRequired.
func requireExpirationExample() {
	fmt.Println("\nExample 7: RequireExpiration for External Tokens")
	fmt.Println("-------------------------------------------------")

	// Hand-craft an HS256 token without an exp claim, standing in for a
	// third-party token this service must accept (see craftTokenWithoutExp).
	externalToken := craftTokenWithoutExp(secretKey)

	// Default processor: accepts the token (it never expires)
	lax := newDefaultProcessor()
	defer func() { _ = lax.Close() }() // best-effort cleanup
	_, err := lax.Parse(externalToken)
	fmt.Printf("Default processor accepts no-exp token: %v\n", err == nil)

	// Strict processor: rejects it
	strictCfg := jwt.DefaultConfig()
	strictCfg.SecretKey = secretKey
	strictCfg.RequireExpiration = true
	strict := mustNew(strictCfg)
	defer func() { _ = strict.Close() }() // best-effort cleanup
	_, err = strict.Parse(externalToken)
	fmt.Printf("RequireExpiration rejects it:          %v\n",
		errors.Is(err, jwt.ErrExpirationRequired))
}

// mustNew builds a processor or terminates the example. Examples use
// log.Fatalf for fatal setup errors to keep the flow linear.
func mustNew(cfg jwt.Config) *jwt.Processor {
	p, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	return p
}

// newDefaultProcessor returns a processor over the example secret with
// DefaultConfig. The caller owns its lifecycle (defer Close).
func newDefaultProcessor() *jwt.Processor {
	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	return mustNew(cfg)
}

// craftTokenWithoutExp builds an HS256 JWT whose payload omits exp, the way a
// non-conforming third-party issuer might. Tokens created by this library
// always carry exp, so this is the only way to demonstrate the case.
func craftTokenWithoutExp(secret string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	// iss matches DefaultConfig's issuer so issuer validation passes
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"external-user","iss":"jwt-service"}`))

	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput)) // never fails per hash.Hash contract
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature
}
