// Package jwt provides comprehensive concurrency and thread-safety tests.
// These tests verify the library is safe for concurrent use in high-load scenarios.
package jwt

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// PROCESSOR CONCURRENT TESTS
// ============================================================================

// TestProcessorConcurrentCreateValidate tests concurrent token creation and validation.
func TestProcessorConcurrentCreateValidate(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numGoroutines = 100
	const numOperations = 50

	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				claims := Claims{
					UserID:   randomUserID(id, j),
					Username: randomUsername(id, j),
					Role:     "user",
				}

				token, err := processor.CreateToken(claims)
				if err != nil {
					errorCount.Add(1)
					continue
				}

				validated, valid, err := processor.ValidateToken(token)
				if err != nil || !valid {
					errorCount.Add(1)
					continue
				}

				if validated.UserID != claims.UserID {
					errorCount.Add(1)
					continue
				}

				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	totalOps := int64(numGoroutines * numOperations)
	if errorCount.Load() > 0 {
		t.Errorf("Concurrent operations had %d errors out of %d operations",
			errorCount.Load(), totalOps)
	}

	t.Logf("Concurrent test passed: %d/%d successful operations",
		successCount.Load(), totalOps)
}

// TestProcessorConcurrentClose tests safe closing during concurrent operations.
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

		wg.Add(numGoroutines + 1) // +1 for the closer goroutine

		// Start token operations
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					claims := Claims{UserID: randomUserID(id, j)}

					token, err := processor.CreateToken(claims)
					if err != nil {
						if err == ErrProcessorClosed {
							return // Expected after close
						}
						continue
					}

					_, _, err = processor.ValidateToken(token)
					if err == ErrProcessorClosed {
						return // Expected after close
					}
				}
			}(i)
		}

		// Close processor concurrently
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond * 100) // Let some operations start
			closeOnce.Do(func() {
				processor.Close()
			})
		}()

		wg.Wait()
	}
}

// TestProcessorConcurrentRefresh tests concurrent token refresh operations.
func TestProcessorConcurrentRefresh(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numGoroutines = 50

	// Create initial refresh tokens
	refreshTokens := make([]string, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		claims := Claims{UserID: randomUserID(i, 0)}
		token, err := processor.CreateRefreshToken(claims)
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
				_, err := processor.RefreshToken(token)
				if err == nil {
					successCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Concurrent refresh test completed: %d successful refreshes", successCount.Load())
}

// TestProcessorConcurrentRevoke tests concurrent token revocation.
func TestProcessorConcurrentRevoke(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig() // Enable default memory store

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numTokens = 100

	// Create tokens
	tokens := make([]string, numTokens)
	for i := 0; i < numTokens; i++ {
		claims := Claims{UserID: randomUserID(i, 0)}
		token, err := processor.CreateToken(claims)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}
		tokens[i] = token
	}

	var wg sync.WaitGroup
	var revokeCount atomic.Int64

	wg.Add(numTokens)

	// Concurrently revoke all tokens
	for i := 0; i < numTokens; i++ {
		go func(idx int) {
			defer wg.Done()
			if err := processor.RevokeToken(tokens[idx]); err == nil {
				revokeCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Verify all tokens are revoked
	for i := 0; i < numTokens; i++ {
		_, valid, _ := processor.ValidateToken(tokens[i])
		if valid {
			t.Errorf("Token %d should be revoked", i)
		}
	}

	t.Logf("Concurrent revoke test completed: %d tokens revoked", revokeCount.Load())
}

// ============================================================================
// RATE LIMITER CONCURRENT TESTS
// ============================================================================

// TestRateLimiterHighConcurrency tests rate limiter under extreme load.
func TestRateLimiterHighConcurrency(t *testing.T) {
	rl := NewRateLimiter(1000, time.Minute)
	defer rl.Close()

	const numGoroutines = 200
	const numRequests = 100

	var wg sync.WaitGroup
	var allowedCount atomic.Int64
	var deniedCount atomic.Int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := "user-" + string(rune('A'+id%26))

			for j := 0; j < numRequests; j++ {
				if rl.Allow(key) {
					allowedCount.Add(1)
				} else {
					deniedCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Rate limiter test: allowed=%d, denied=%d",
		allowedCount.Load(), deniedCount.Load())
}

// TestRateLimiterConcurrentAllowN tests AllowN under concurrent access.
func TestRateLimiterConcurrentAllowN(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	defer rl.Close()

	const numGoroutines = 50

	var wg sync.WaitGroup
	var successCount atomic.Int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := "batch-user"

			for j := 0; j < 20; j++ {
				n := (j % 5) + 1 // Request 1-5 tokens
				if rl.AllowN(key, n) {
					successCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("AllowN concurrent test completed: %d successful batches", successCount.Load())
}

// TestRateLimiterConcurrentResetAndAllow tests concurrent reset and allow operations.
func TestRateLimiterConcurrentResetAndAllow(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Close()

	const numGoroutines = 100
	const numOperations = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := "shared-key"

			for j := 0; j < numOperations; j++ {
				switch j % 3 {
				case 0:
					rl.Allow(key)
				case 1:
					rl.Reset(key)
				case 2:
					rl.AllowN(key, 2)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestRateLimiterConcurrentClose tests closing rate limiter during operations.
func TestRateLimiterConcurrentClose(t *testing.T) {
	const numIterations = 30

	for iter := 0; iter < numIterations; iter++ {
		rl := NewRateLimiter(100, time.Minute)

		const numGoroutines = 20
		var wg sync.WaitGroup
		var closeOnce sync.Once

		wg.Add(numGoroutines + 1)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				key := "user-" + string(rune('A'+id))
				for j := 0; j < 50; j++ {
					rl.Allow(key)
				}
			}(i)
		}

		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond * 10)
			closeOnce.Do(func() {
				rl.Close()
			})
		}()

		wg.Wait()
	}
}

// Note: TestBlacklistConcurrentOperations moved to blacklist_test.go

// ============================================================================
// CLAIMS POOL CONCURRENT TESTS
// ============================================================================

// TestClaimsPoolConcurrentAccess tests the claims pool under high concurrency.
func TestClaimsPoolConcurrentAccess(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numGoroutines = 200
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				claims := Claims{
					UserID:      randomUserID(id, j),
					Username:    randomUsername(id, j),
					Permissions: []string{"read", "write"},
					Scopes:      []string{"api", "admin"},
					Extra: map[string]any{
						"department": "engineering",
						"level":      fmt.Sprintf("%d", id%10),
					},
				}

				token, err := processor.CreateToken(claims)
				if err != nil {
					t.Errorf("CreateToken failed: %v", err)
					return
				}

				validated, valid, err := processor.ValidateToken(token)
				if err != nil || !valid {
					t.Errorf("ValidateToken failed: valid=%v, err=%v", valid, err)
					return
				}

				// Verify extra fields
				if validated.Extra == nil {
					t.Errorf("Extra field is nil")
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

// ============================================================================
// STRESS TESTS
// ============================================================================

// TestStressHighLoad simulates extreme load conditions.
func TestStressHighLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	const numGoroutines = 500
	const numOperations = 100

	var wg sync.WaitGroup
	var totalOps atomic.Int64
	var errorOps atomic.Int64

	wg.Add(numGoroutines)

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				totalOps.Add(1)

				claims := Claims{UserID: randomUserID(id, j)}

				token, err := processor.CreateToken(claims)
				if err != nil {
					errorOps.Add(1)
					continue
				}

				_, valid, err := processor.ValidateToken(token)
				if err != nil || !valid {
					errorOps.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	elapsed := time.Since(start)
	total := totalOps.Load()
	errors := errorOps.Load()
	opsPerSec := float64(total) / elapsed.Seconds()

	t.Logf("Stress test completed:")
	t.Logf("  Total operations: %d", total)
	t.Logf("  Errors: %d (%.2f%%)", errors, float64(errors)/float64(total)*100)
	t.Logf("  Duration: %v", elapsed)
	t.Logf("  Operations/sec: %.0f", opsPerSec)

	if errors > 0 {
		t.Errorf("Stress test had %d errors", errors)
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func randomUserID(goroutineID, opID int) string {
	return string(rune('A'+goroutineID%26)) + string(rune('0'+opID%10))
}

func randomUsername(goroutineID, opID int) string {
	return "user_" + randomUserID(goroutineID, opID)
}
