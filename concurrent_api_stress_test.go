package jwt

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// P-002 concurrency-audit stress tests. The Create/Validate close race,
// goroutine-leak counting, and HMAC pool draining are covered by
// concurrent_test.go and resource_leak_test.go; this file closes the remaining
// gaps: every public method racing a concurrent Close (plus the concurrent
// double-Close CAS), and — in the internal package — blacklist-store
// saturation under lock contention.

// TestProcessorAllMethodsVsClose hammers every public Processor method against
// a concurrent Close and a concurrent second Close. Contract under test: no
// panic and no data race under -race; every returned error is ErrProcessorClosed
// (the close won) or one of the method's documented outcomes (the operation
// won); and exactly one of the two racing Close calls succeeds (CAS).
func TestProcessorAllMethodsVsClose(t *testing.T) {
	const iterations = 15

	for iter := range iterations {
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.Blacklist = DefaultBlacklistConfig()
		cfg.RotateRefreshTokens = true
		processor, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}

		// Pre-mint every input the methods need, so outcomes depend only on
		// the close race, never on token availability.
		basic := &Claims{UserID: "stress", Username: "stress"}
		custom := &TestCustomClaims{UserID: "stress", Email: "stress@example.com"}
		access, err := processor.Create(basic)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		refresh, err := processor.CreateRefresh(basic)
		if err != nil {
			t.Fatalf("CreateRefresh: %v", err)
		}
		accessCustom, err := processor.Create(custom)
		if err != nil {
			t.Fatalf("Create (custom): %v", err)
		}
		refreshCustom, err := processor.CreateRefresh(custom)
		if err != nil {
			t.Fatalf("CreateRefresh (custom): %v", err)
		}

		// allowed verifies an operation error is a documented outcome. Besides
		// ErrProcessorClosed, Refresh may see ErrTokenRevoked: rotation
		// blacklists the refresh token after the first racing Refresh wins.
		allowed := func(method string, err error) {
			switch {
			case err == nil, errors.Is(err, ErrProcessorClosed), errors.Is(err, ErrTokenRevoked):
			default:
				t.Errorf("%s: unexpected error: %v", method, err)
			}
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		run := func(op func()) {
			wg.Go(func() {
				<-start
				op()
			})
		}

		for range 4 {
			run(func() {
				_, err := processor.Create(basic)
				allowed("Create", err)
			})
			run(func() {
				_, err := processor.CreateRefresh(basic)
				allowed("CreateRefresh", err)
			})
			run(func() {
				_, err := processor.Parse(access)
				allowed("Parse", err)
			})
			run(func() {
				_, err := processor.ParseInto(accessCustom, &TestCustomClaims{})
				allowed("ParseInto", err)
			})
			run(func() {
				_, err := processor.Refresh(refresh)
				allowed("Refresh", err)
			})
			run(func() {
				_, err := processor.RefreshInto(refreshCustom, &TestCustomClaims{})
				allowed("RefreshInto", err)
			})
			run(func() {
				err := processor.Revoke(refresh)
				allowed("Revoke", err)
			})
			run(func() {
				_, err := processor.IsRevoked(refresh)
				allowed("IsRevoked", err)
			})
			run(func() {
				var out Claims
				err := processor.ParseUnverified(access, &out)
				allowed("ParseUnverified", err)
			})
		}

		// Two racing Closes: the atomic.Bool CAS must let exactly one win.
		closeErrs := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				<-start
				closeErrs <- processor.Close()
			})
		}

		close(start)
		wg.Wait()
		close(closeErrs)

		nilCloses := 0
		for err := range closeErrs {
			switch {
			case err == nil:
				nilCloses++
			case errors.Is(err, ErrProcessorClosed):
			default:
				t.Fatalf("Close returned undocumented error in iteration %d: %v", iter, err)
			}
		}
		if nilCloses != 1 {
			t.Fatalf("iteration %d: exactly one racing Close must win the CAS, got %d", iter, nilCloses)
		}
	}
}

// TestProcessorConcurrentIsRevokedRevokeValidate drives the blacklist read
// path (IsRevoked, Validate) against concurrent writes (Revoke) on a shared
// token, asserting the eventual-consistency contract: once Revoke reports
// success, every subsequent IsRevoked/Validate must observe the revocation.
func TestProcessorConcurrentIsRevokedRevokeValidate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	const numTokens = 40
	tokens := make([]string, numTokens)
	for i := range numTokens {
		token, err := processor.Create(&Claims{UserID: fmt.Sprintf("rr-%d", i)})
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		tokens[i] = token
	}

	var wg sync.WaitGroup
	for i := range numTokens {
		wg.Add(3)
		go func(token string) {
			defer wg.Done()
			if err := processor.Revoke(token); err != nil {
				t.Errorf("Revoke: %v", err)
			}
		}(tokens[i])
		go func(token string) {
			defer wg.Done()
			if _, err := processor.IsRevoked(token); err != nil {
				t.Errorf("IsRevoked: %v", err)
			}
		}(tokens[i])
		go func(token string) {
			defer wg.Done()
			if _, _, err := processor.Validate(token); err != nil && !errors.Is(err, ErrTokenRevoked) {
				t.Errorf("Validate: %v", err)
			}
		}(tokens[i])
	}
	wg.Wait()

	// After all revocations complete, every token must be observed revoked.
	for i, token := range tokens {
		revoked, err := processor.IsRevoked(token)
		if err != nil {
			t.Fatalf("IsRevoked %d after revoke: %v", i, err)
		}
		if !revoked {
			t.Errorf("token %d must be revoked after successful Revoke", i)
		}
	}
}
