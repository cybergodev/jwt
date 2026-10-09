package jwt

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// Concurrency tests for the Processor. RateLimiter concurrency tests live in
// ratelimit_test.go. TestProcessorCloseUnderLoad's goroutine-leak angle is
// covered more strongly by TestNoGoroutineLeakAfterClose in
// resource_leak_test.go, which counts goroutines; the close race itself is
// covered by TestProcessorConcurrentClose below.

// TestProcessorConcurrentCreateValidate drives concurrent Create/Validate
// pairs with rich claims (permissions, scopes, extra map), which also
// exercises the pooled Claims reset path under contention.
func TestProcessorConcurrentCreateValidate(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	const numGoroutines = 100
	const numOperations = 50

	var wg sync.WaitGroup
	var errorCount atomic.Int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				claims := Claims{
					UserID:      fmt.Sprintf("g%d_op%d", id, j),
					Username:    fmt.Sprintf("user_g%d_op%d", id, j),
					Role:        "user",
					Permissions: []string{"read", "write"},
					Scopes:      []string{"api", "admin"},
					Extra: map[string]any{
						"department": "engineering",
						"level":      fmt.Sprintf("%d", id%10),
					},
				}

				token, err := processor.Create(&claims)
				if err != nil {
					errorCount.Add(1)
					continue
				}

				validated, valid, err := processor.Validate(token)
				if err != nil || !valid {
					errorCount.Add(1)
					continue
				}

				if validated.UserID != claims.UserID || validated.Extra == nil {
					errorCount.Add(1)
					continue
				}
			}
		}(i)
	}

	wg.Wait()

	if errorCount.Load() > 0 {
		t.Errorf("Concurrent operations had %d errors out of %d operations",
			errorCount.Load(), numGoroutines*numOperations)
	}
}

func TestProcessorConcurrentClose(t *testing.T) {
	const numIterations = 50

	for iter := 0; iter < numIterations; iter++ {
		processor, err := newTestProcessor(testSecretKey)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}

		const numGoroutines = 20
		var wg sync.WaitGroup
		var closeOnce sync.Once

		wg.Add(numGoroutines + 1)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					claims := Claims{UserID: fmt.Sprintf("g%d_op%d", id, j)}

					token, err := processor.Create(&claims)
					if err != nil {
						if err == ErrProcessorClosed {
							return
						}
						continue
					}

					_, _, err = processor.Validate(token)
					if err == ErrProcessorClosed {
						return
					}
				}
			}(i)
		}

		go func() {
			defer wg.Done()
			closeOnce.Do(func() {
				_ = processor.Close() // cleanup
			})
		}()

		wg.Wait()
	}
}

func TestProcessorConcurrentRefresh(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	const numGoroutines = 50

	refreshTokens := make([]string, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		claims := Claims{UserID: fmt.Sprintf("refresh_g%d", i)}
		token, err := processor.CreateRefresh(&claims)
		if err != nil {
			t.Fatalf("Failed to create refresh token: %v", err)
		}
		refreshTokens[i] = token
	}

	var wg sync.WaitGroup
	var successCount atomic.Int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			token := refreshTokens[idx]

			for j := 0; j < 5; j++ {
				_, err := processor.Refresh(token)
				if err == nil {
					successCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() == 0 {
		t.Error("Expected at least one successful refresh")
	}
}

func TestProcessorConcurrentRevoke(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	const numTokens = 100

	tokens := make([]string, numTokens)
	for i := 0; i < numTokens; i++ {
		claims := Claims{UserID: fmt.Sprintf("revoke_g%d", i)}
		token, err := processor.Create(&claims)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}
		tokens[i] = token
	}

	var wg sync.WaitGroup
	var revokeCount atomic.Int64

	wg.Add(numTokens)

	for i := 0; i < numTokens; i++ {
		go func(idx int) {
			defer wg.Done()
			if err := processor.Revoke(tokens[idx]); err == nil {
				revokeCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Verify all tokens are revoked
	for i := 0; i < numTokens; i++ {
		_, valid, _ := processor.Validate(tokens[i])
		if valid {
			t.Errorf("Token %d should be revoked", i)
		}
	}

	if revokeCount.Load() != numTokens {
		t.Errorf("Expected %d revocations, got %d", numTokens, revokeCount.Load())
	}
}
