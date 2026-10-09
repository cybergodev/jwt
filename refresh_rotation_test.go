package jwt

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// newRotationProcessor returns a processor with RotateRefreshTokens enabled.
func newRotationProcessor(t *testing.T) *Processor {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.RotateRefreshTokens = true
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return p
}

// TestRefreshRotationDisabledByDefault covers the historical default: without
// RotateRefreshTokens the old refresh token stays valid after a Refresh.
func TestRefreshRotationDisabledByDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	refresh, err := p.CreateRefresh(&Claims{UserID: "rot-user", Username: "alice"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}
	if _, err := p.Refresh(refresh); err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}
	if _, err := p.Refresh(refresh); err != nil {
		t.Errorf("default: old refresh token should still be usable, err = %v", err)
	}
}

// TestRefreshRotationRevokesOldToken covers the opt-in one-time-use semantics:
// after a successful Refresh the old refresh token is rejected with
// ErrTokenRevoked, while the newly minted access token validates.
func TestRefreshRotationRevokesOldToken(t *testing.T) {
	p := newRotationProcessor(t)
	defer func() { _ = p.Close() }() // best-effort cleanup

	refresh, err := p.CreateRefresh(&Claims{UserID: "rot-user", Username: "alice"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}

	access, err := p.Refresh(refresh)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, err := p.Parse(access); err != nil {
		t.Errorf("new access token should parse: %v", err)
	}

	_, err = p.Refresh(refresh)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("rotated token should be rejected with ErrTokenRevoked, err = %v", err)
	}

	revoked, err := p.IsRevoked(refresh)
	if err != nil || !revoked {
		t.Errorf("IsRevoked() = %v, %v; want true, nil", revoked, err)
	}
}

// TestRefreshRotationRateLimitBurn covers the documented fail-closed ordering:
// rotation revokes the old token BEFORE minting, so when minting fails — here
// because the rate limit trips — the old refresh token is already burned and a
// later Refresh reports ErrTokenRevoked instead of minting again.
func TestRefreshRotationRateLimitBurn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.RotateRefreshTokens = true
	cfg.EnableRateLimit = true
	cfg.RateLimitRate = 1
	cfg.RateLimitWindow = time.Hour
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	// The single-token bucket is consumed by this creation.
	refresh, err := p.CreateRefresh(&Claims{UserID: "rot-burn", Username: "dave"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}

	// Rotation revokes the old jti, then minting trips the rate limit.
	access, err := p.Refresh(refresh)
	if !errors.Is(err, ErrRateLimitExceeded) {
		t.Fatalf("errors.Is(err, ErrRateLimitExceeded) = false, err = %v", err)
	}
	if access != "" {
		t.Error("no token should be issued when the rate limit trips")
	}

	// The burn: the same token now fails at validation with ErrTokenRevoked.
	_, err = p.Refresh(refresh)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("burned token should report ErrTokenRevoked, err = %v", err)
	}
}

// TestRefreshRotationRefreshInto mirrors TestRefreshRotationRevokesOldToken
// on the custom-claims path.
func TestRefreshRotationRefreshInto(t *testing.T) {
	p := newRotationProcessor(t)
	defer func() { _ = p.Close() }() // best-effort cleanup

	refresh, err := p.CreateRefresh(&TestCustomClaims{
		UserID: "rot-custom",
		Email:  "rot@example.com",
	})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}

	into := &TestCustomClaims{UserID: "rot-custom", Email: "rot@example.com"}
	if _, err := p.RefreshInto(refresh, into); err != nil {
		t.Fatalf("RefreshInto() error = %v", err)
	}

	_, err = p.RefreshInto(refresh, &TestCustomClaims{UserID: "x", Email: "y@example.com"})
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("rotated token should be rejected with ErrTokenRevoked, err = %v", err)
	}
}

// TestRefreshRotationRequiresJTI signs a refresh token without a jti directly
// (bypassing setRegisteredDefaults, which always generates one) and expects
// rotation to reject it with ErrTokenMissingID: a token that cannot be
// revoked must not be refreshable under one-time-use semantics.
func TestRefreshRotationRequiresJTI(t *testing.T) {
	p := newRotationProcessor(t)
	defer func() { _ = p.Close() }() // best-effort cleanup

	claims := &Claims{
		UserID: "rot-nojti",
		RegisteredClaims: RegisteredClaims{
			Issuer:    "jwt-service", // DefaultConfig issuer
			ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
			TokenType: TokenTypeRefresh,
		},
	}
	token, err := p.signClaims(claims)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	_, err = p.Refresh(token)
	if !errors.Is(err, ErrTokenMissingID) {
		t.Errorf("errors.Is(err, ErrTokenMissingID) = false, err = %v", err)
	}
}

// errRotationStore is the sentinel a failing store returns from Add, so the
// test can assert it stays reachable through the double-%w wrap.
var errRotationStore = errors.New("rotation store unavailable")

// rotationFailingStore is a BlacklistStore whose Add always fails.
type rotationFailingStore struct{}

func (s *rotationFailingStore) Add(string, time.Time) error { return errRotationStore }
func (s *rotationFailingStore) Contains(string) (bool, error) {
	return false, nil
}
func (s *rotationFailingStore) Close() error { return nil }

// TestRefreshRotationStoreFailure asserts the fail-closed contract when the
// blacklist store rejects the revocation: no new token is issued and both the
// ErrRefreshRotationFailed sentinel and the store error are errors.Is-reachable.
func TestRefreshRotationStoreFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.RotateRefreshTokens = true
	cfg.Blacklist = BlacklistConfig{Store: &rotationFailingStore{}}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	refresh, err := p.CreateRefresh(&Claims{UserID: "rot-store", Username: "bob"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}

	access, err := p.Refresh(refresh)
	if !errors.Is(err, ErrRefreshRotationFailed) {
		t.Fatalf("errors.Is(err, ErrRefreshRotationFailed) = false, err = %v", err)
	}
	if !errors.Is(err, errRotationStore) {
		t.Errorf("store error should remain wrapped: err = %v", err)
	}
	if access != "" {
		t.Error("no token should be issued when rotation revocation fails")
	}
}

// TestRefreshRotationConcurrent documents the race semantics: concurrent
// Refresh calls on the same token may both succeed (both pass validation
// before either revocation lands), but at least one must succeed and no
// caller may see an error other than ErrTokenRevoked.
func TestRefreshRotationConcurrent(t *testing.T) {
	p := newRotationProcessor(t)
	defer func() { _ = p.Close() }() // best-effort cleanup

	refresh, err := p.CreateRefresh(&Claims{UserID: "rot-conc", Username: "carol"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}

	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, errs[i] = p.Refresh(refresh)
		})
	}
	wg.Wait()

	var ok int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrTokenRevoked):
			// Lost the rotation race — expected.
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok == 0 {
		t.Error("at least one concurrent Refresh should succeed")
	}
}
