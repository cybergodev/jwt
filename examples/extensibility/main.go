// Package main demonstrates extensibility features not shown in the other
// examples:
//   - Audience validation (ExpectedAudience)
//   - Clock injection (FixedClock) and clock-skew tolerance, for
//     deterministic, sleep-free testing of expiry behavior
//   - Custom BlacklistStore backend (e.g. Redis)
//   - Consumer-side narrow interfaces for dependency injection
//
// Run with: go run ./examples/extensibility
package main

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cybergodev/jwt"
)

func main() {
	fmt.Println("JWT Library - Extensibility")
	fmt.Println("===========================")

	const secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Example 1: Audience validation
	audienceExample(secretKey)

	fmt.Println()

	// Example 2: Clock injection and ClockSkew
	clockExample(secretKey)

	fmt.Println()

	// Example 3: Custom blacklist store
	customStoreExample(secretKey)

	fmt.Println()

	// Example 4: Consumer-side interfaces
	narrowInterfaceExample(secretKey)

	fmt.Println("\nExtensibility example complete!")
}

// audienceExample shows issuer/audience (iss/aud) enforcement.
// Tokens whose aud claim does not contain ExpectedAudience are rejected.
func audienceExample(secretKey string) {
	fmt.Println("Example 1: Audience Validation")
	fmt.Println("------------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.ExpectedAudience = "billing-api" // reject tokens without this audience
	p, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	// Audience is a registered claim; set it via the embedded RegisteredClaims.
	// (Promoted fields cannot be named directly in a composite literal.)
	matchingClaims := jwt.Claims{
		UserID: "user-billing",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.StringOrSlice{"billing-api"},
		},
	}
	token, err := p.Create(&matchingClaims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	_, err = p.Parse(token)
	fmt.Printf("Token for billing-api: valid=%v\n", err == nil)

	// A token issued for a different audience is rejected by Parse.
	mismatchClaims := jwt.Claims{
		UserID: "user-admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.StringOrSlice{"admin-api"},
		},
	}
	mismatchToken, err := p.Create(&mismatchClaims)
	if err != nil {
		log.Fatalf("Failed to create mismatch token: %v", err)
	}
	_, err = p.Parse(mismatchToken)
	fmt.Printf("Token for admin-api:   valid=%v (audience mismatch=%v)\n",
		err == nil, errors.Is(err, jwt.ErrTokenInvalidAudience))
}

// clockExample shows FixedClock-based time injection. By pointing the issuer
// and validator at different fixed instants with the same key, token expiry
// can be exercised deterministically without time.Sleep — then ClockSkew
// shows how a validator tolerates that drift.
func clockExample(secretKey string) {
	fmt.Println("Example 2: Clock Injection and ClockSkew")
	fmt.Println("----------------------------------------")

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Issuer's clock is "now"; token expires after 1 minute.
	issuerCfg := jwt.DefaultConfig()
	issuerCfg.SecretKey = secretKey
	issuerCfg.Clock = jwt.FixedClock{T: now}
	issuerCfg.AccessTokenTTL = time.Minute
	issuer, err := jwt.New(issuerCfg)
	if err != nil {
		log.Fatalf("Failed to create issuer: %v", err)
	}
	defer func() { _ = issuer.Close() }() // best-effort cleanup

	token, err := issuer.Create(&jwt.Claims{UserID: "clock-user"})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	// Same key, but the validator's clock is 2 minutes later -> token expired.
	strictCfg := jwt.DefaultConfig()
	strictCfg.SecretKey = secretKey
	strictCfg.Clock = jwt.FixedClock{T: now.Add(2 * time.Minute)}
	strictCfg.AccessTokenTTL = time.Minute
	strict, err := jwt.New(strictCfg)
	if err != nil {
		log.Fatalf("Failed to create strict validator: %v", err)
	}
	defer func() { _ = strict.Close() }() // best-effort cleanup

	_, err = strict.Parse(token)
	fmt.Printf("Strict clock 2 min past issue: valid=%v (expired=%v)\n",
		err == nil, errors.Is(err, jwt.ErrTokenExpired))

	// ClockSkew applies leeway to exp/nbf so the validator accepts tokens
	// issued by clocks running ahead — here 2 minutes of tolerance absorbs
	// the 2-minute drift.
	skewCfg := jwt.DefaultConfig()
	skewCfg.SecretKey = secretKey
	skewCfg.Clock = jwt.FixedClock{T: now.Add(2 * time.Minute)}
	skewCfg.AccessTokenTTL = time.Minute
	skewCfg.ClockSkew = 2 * time.Minute
	tolerant, err := jwt.New(skewCfg)
	if err != nil {
		log.Fatalf("Failed to create tolerant validator: %v", err)
	}
	defer func() { _ = tolerant.Close() }() // best-effort cleanup

	_, err = tolerant.Parse(token)
	fmt.Printf("ClockSkew=2m on same validator: valid=%v\n", err == nil)
}

// memoryBlacklistStore is a minimal BlacklistStore backed by a map.
// Implementations for production use Redis, a database, etc. — the interface
// is the same. It must be safe for concurrent use.
type memoryBlacklistStore struct {
	mu    sync.Mutex
	items map[string]time.Time // tokenID -> expiry
	now   func() time.Time
}

func newMemoryBlacklistStore() *memoryBlacklistStore {
	return &memoryBlacklistStore{
		items: make(map[string]time.Time),
		now:   time.Now,
	}
}

// Add records a token ID with its expiry time.
func (s *memoryBlacklistStore) Add(tokenID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[tokenID] = expiresAt
	return nil
}

// Contains reports whether the token ID is present and not expired.
func (s *memoryBlacklistStore) Contains(tokenID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.items[tokenID]
	if !ok {
		return false, nil
	}
	if s.now().After(exp) {
		delete(s.items, tokenID) // lazy expiry
		return false, nil
	}
	return true, nil
}

// Close releases resources (none for this in-memory implementation).
func (s *memoryBlacklistStore) Close() error { return nil }

// customStoreExample wires a custom BlacklistStore into the processor.
// Revoke/IsRevoked/Parse then consult the custom backend transparently.
func customStoreExample(secretKey string) {
	fmt.Println("Example 3: Custom Blacklist Store")
	fmt.Println("---------------------------------")

	store := newMemoryBlacklistStore()

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	// Providing Store makes the processor use it for all blacklist operations;
	// MaxSize/CleanupInterval/EnableAutoCleanup are ignored with a custom store.
	// Ownership note: Processor.Close also closes the store.
	cfg.Blacklist = jwt.BlacklistConfig{Store: store}
	p, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&jwt.Claims{UserID: "store-user", Username: "store-user"})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	revokedBefore, _ := p.IsRevoked(token)
	if err := p.Revoke(token); err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}
	revokedAfter, _ := p.IsRevoked(token)
	_, err = p.Parse(token)
	fmt.Printf("Custom store revocation: before=%v, after=%v, validate rejected=%v\n",
		revokedBefore, revokedAfter, err != nil)
}

// tokenIssuer is a consumer-side interface: only the methods this example
// actually calls. Define interfaces where they are consumed, not in the
// library — *jwt.Processor satisfies them automatically, which keeps
// production code and test doubles interchangeable.
type tokenIssuer interface {
	Create(claims jwt.CustomClaims) (string, error)
	Parse(tokenString string) (jwt.Claims, error)
}

// narrowInterfaceExample shows dependency injection through a narrow
// consumer-side interface instead of the wide jwt.TokenManager facade.
func narrowInterfaceExample(secretKey string) {
	fmt.Println("Example 4: Consumer-Side Interfaces")
	fmt.Println("-----------------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	processor, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// *jwt.Processor is passed as the narrow interface
	var issuer tokenIssuer = processor
	issueAndEcho(issuer, "di-user")
}

// issueAndEcho depends on the two-method interface, not on *jwt.Processor —
// a test can supply any implementation.
func issueAndEcho(issuer tokenIssuer, userID string) {
	token, err := issuer.Create(&jwt.Claims{UserID: userID, Username: userID})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	claims, err := issuer.Parse(token)
	if err != nil {
		log.Fatalf("Failed to parse token: %v", err)
	}
	fmt.Printf("Issued and verified through narrow interface - User: %s\n", claims.UserID)
}
