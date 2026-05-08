package jwt

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessorConcurrentCreateValidate(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

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
					UserID:   fmt.Sprintf("g%d_op%d", id, j),
					Username: fmt.Sprintf("user_g%d_op%d", id, j),
					Role:     "user",
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
			time.Sleep(time.Microsecond * 100)
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
			key := fmt.Sprintf("user-%d", id%26)

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

	total := allowedCount.Load() + deniedCount.Load()
	if total != numGoroutines*numRequests {
		t.Errorf("Expected %d total operations, got %d", numGoroutines*numRequests, total)
	}
}

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
				n := (j % 5) + 1
				if rl.AllowN(key, n) {
					successCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() == 0 {
		t.Error("Expected at least one successful AllowN batch")
	}
}

func TestRateLimiterConcurrentResetAndAllow(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Close()

	const numGoroutines = 100
	const numOperations = 50

	var wg sync.WaitGroup
	var allowedCount atomic.Int64

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := "shared-key"

			for j := 0; j < numOperations; j++ {
				switch j % 3 {
				case 0:
					if rl.Allow(key) {
						allowedCount.Add(1)
					}
				case 1:
					rl.Reset(key)
				case 2:
					if rl.AllowN(key, 2) {
						allowedCount.Add(1)
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// After Reset clears the bucket, Allow should succeed again.
	// With 100 goroutines doing 50 ops each, some Allow/AllowN must succeed.
	if allowedCount.Load() == 0 {
		t.Error("Expected at least one successful allow after resets")
	}
}

func TestRateLimiterConcurrentClose(t *testing.T) {
	const numIterations = 30

	for iter := 0; iter < numIterations; iter++ {
		rl := NewRateLimiter(100, time.Minute)

		const numGoroutines = 20
		var wg sync.WaitGroup
		var closeOnce sync.Once
		var opsSuccess atomic.Int64

		wg.Add(numGoroutines + 1)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("user-%d", id)
				for j := 0; j < 50; j++ {
					if rl.Allow(key) {
						opsSuccess.Add(1)
					}
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

func TestClaimsPoolConcurrentAccess(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	const numGoroutines = 200
	const numOperations = 100

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
					return
				}

				validated, valid, err := processor.Validate(token)
				if err != nil || !valid {
					errorCount.Add(1)
					return
				}

				if validated.Extra == nil {
					errorCount.Add(1)
					return
				}
			}
		}(i)
	}

	wg.Wait()

	if errorCount.Load() > 0 {
		t.Errorf("Claims pool concurrent test had %d errors", errorCount.Load())
	}
}

func TestStressHighLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

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

				claims := Claims{UserID: fmt.Sprintf("g%d_op%d", id, j)}

				token, err := processor.Create(&claims)
				if err != nil {
					errorOps.Add(1)
					continue
				}

				_, valid, err := processor.Validate(token)
				if err != nil || !valid {
					errorOps.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	elapsed := time.Since(start)
	total := totalOps.Load()
	errs := errorOps.Load()

	t.Logf("Stress test: %d ops in %v (%.0f ops/sec), %d errors (%.2f%%)",
		total, elapsed, float64(total)/elapsed.Seconds(), errs, float64(errs)/float64(total)*100)

	if errs > 0 {
		t.Errorf("Stress test had %d errors", errs)
	}
}
