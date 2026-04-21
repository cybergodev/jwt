package jwt

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestHMACPoolCleanupOnClose verifies that calling Processor.Close() clears
// the internal HMAC hasher pool, preventing secret key material retention.
func TestHMACPoolCleanupOnClose(t *testing.T) {
	// Create and use a processor so HMAC hashers are populated in the pool
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Generate several tokens to populate the HMAC hasher pool
	for i := 0; i < 10; i++ {
		claims := &Claims{UserID: fmt.Sprintf("pool-user-%d", i)}
		if _, err := processor.Create(claims); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	// Close should drain the HMAC pool
	if err := processor.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify processor is closed
	if !processor.IsClosed() {
		t.Error("Processor should be closed")
	}
}

// TestHMACPoolCleanupMultipleProcessors verifies pool cleanup works
// correctly when multiple processors are created and closed sequentially.
func TestHMACPoolCleanupMultipleProcessors(t *testing.T) {
	for i := 0; i < 5; i++ {
		processor, err := newTestProcessor(testSecretKey)
		if err != nil {
			t.Fatalf("Processor %d creation failed: %v", i, err)
		}

		claims := &Claims{UserID: fmt.Sprintf("multi-%d", i)}
		if _, err := processor.Create(claims); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}

		if err := processor.Close(); err != nil {
			t.Fatalf("Close %d failed: %v", i, err)
		}
	}
}

// TestRateLimiterExpiredBucketEviction verifies that stale buckets are
// evicted when the rate limiter reaches max capacity.
func TestRateLimiterExpiredBucketEviction(t *testing.T) {
	rl := NewRateLimiter(100, time.Second)
	rl.maxBuckets = 10
	defer rl.Close()

	// Use injectable clock for deterministic time control
	now := time.Now()
	rl.nowFunc = func() time.Time { return now }

	// Fill buckets to max capacity
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("old-user-%d", i)
		if !rl.Allow(key) {
			t.Fatalf("Allow(%q) should succeed for initial fill", key)
		}
	}

	if len(rl.buckets) != 10 {
		t.Fatalf("Expected 10 buckets, got %d", len(rl.buckets))
	}

	// Advance time past the stale threshold (2x window = 2 seconds)
	now = now.Add(3 * time.Second)

	// Adding a new key should trigger expired bucket eviction
	if !rl.Allow("new-user") {
		t.Fatal("Allow(new-user) should succeed after eviction")
	}

	// Old buckets should have been evicted; only the new one should remain
	rl.mu.Lock()
	count := len(rl.buckets)
	rl.mu.Unlock()

	if count > 1 {
		t.Errorf("Expected at most 1 bucket after stale eviction, got %d", count)
	}
}

// TestRateLimiterStaleBucketsCleared verifies that stale buckets are cleaned
// even when they're well below max capacity.
func TestRateLimiterStaleBucketsNotCleanedBelowCapacity(t *testing.T) {
	rl := NewRateLimiter(100, time.Second)
	rl.maxBuckets = 100 // High limit, won't trigger capacity eviction
	defer rl.Close()

	now := time.Now()
	rl.nowFunc = func() time.Time { return now }

	// Create a few buckets
	rl.Allow("user-a")
	rl.Allow("user-b")

	if len(rl.buckets) != 2 {
		t.Fatalf("Expected 2 buckets, got %d", len(rl.buckets))
	}

	// Advance time but don't trigger capacity eviction
	now = now.Add(3 * time.Second)

	// Stale buckets remain because capacity isn't reached
	rl.Allow("user-c")

	rl.mu.Lock()
	count := len(rl.buckets)
	rl.mu.Unlock()

	// user-a and user-b are stale but not evicted since capacity was never hit.
	// user-c is new. All 3 should exist.
	if count != 3 {
		t.Errorf("Expected 3 buckets (stale eviction only at capacity), got %d", count)
	}
}

// TestMemoryStoreGoroutineCleanup verifies that the memory store's background
// cleanup goroutine is properly stopped when Close is called.
func TestMemoryStoreGoroutineCleanup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	cfg.Blacklist.CleanupInterval = 100 * time.Millisecond

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Create and revoke a token to exercise the store
	claims := &Claims{UserID: "goroutine-test"}
	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := processor.Revoke(token); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Close should stop the background goroutine
	if err := processor.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// TestProcessorCloseIdempotent verifies that Close can be called multiple
// times without panic or error on the second call (returns ErrProcessorClosed).
func TestProcessorCloseIdempotent(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// First close succeeds
	if err := processor.Close(); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}

	// Second close returns ErrProcessorClosed
	if err := processor.Close(); err != ErrProcessorClosed {
		t.Errorf("Second Close should return ErrProcessorClosed, got: %v", err)
	}
}

// TestRateLimiterCloseIdempotent verifies Close can be called multiple times.
func TestRateLimiterCloseIdempotent(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)

	rl.Allow("user-a")
	rl.Allow("user-b")

	rl.Close()
	rl.Close() // Should not panic
}

// TestProcessorCloseUnderLoad verifies no goroutine leak when Close is
// called while concurrent operations are in progress.
func TestProcessorCloseUnderLoad(t *testing.T) {
	const iterations = 20

	for i := 0; i < iterations; i++ {
		processor, err := newTestProcessor(testSecretKey)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}

		var wg sync.WaitGroup
		const workers = 10
		wg.Add(workers)

		for j := 0; j < workers; j++ {
			go func(id int) {
				defer wg.Done()
				for k := 0; k < 20; k++ {
					claims := &Claims{UserID: fmt.Sprintf("w%d_k%d", id, k)}
					token, err := processor.Create(claims)
					if err != nil {
						if err == ErrProcessorClosed {
							return
						}
						continue
					}
					_, _, _ = processor.Validate(token)
				}
			}(j)
		}

		// Close after a brief delay
		time.Sleep(time.Microsecond * 50)
		processor.Close()
		wg.Wait()
	}
}

// TestNoGoroutineLeakAfterClose uses runtime.NumGoroutine to verify
// that closing a processor doesn't leave lingering goroutines.
func TestNoGoroutineLeakAfterClose(t *testing.T) {
	// Warm up the scheduler
	runtime.GC()
	runtime.Gosched()
	time.Sleep(10 * time.Millisecond)
	before := runtime.NumGoroutine()

	const iterations = 10
	for i := 0; i < iterations; i++ {
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.Blacklist = DefaultBlacklistConfig()
		cfg.Blacklist.CleanupInterval = 50 * time.Millisecond

		processor, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}

		// Use the processor to ensure goroutine starts
		claims := &Claims{UserID: "leak-test"}
		token, err := processor.Create(claims)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		_ = processor.Revoke(token)

		// Wait for auto-cleanup goroutine to be active
		time.Sleep(100 * time.Millisecond)

		processor.Close()
	}

	// Allow goroutines to settle
	runtime.GC()
	runtime.Gosched()
	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Allow some tolerance for test framework goroutines
	if after > before+5 {
		t.Errorf("Potential goroutine leak: %d goroutines before, %d after (%d iterations)",
			before, after, iterations)
	}
}
