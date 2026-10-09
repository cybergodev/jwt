package jwt

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// RateLimiter unit, eviction, overflow, and concurrency tests, consolidated
// from coverage_test.go, resource_leak_test.go, concurrent_test.go, and the
// former ratelimit_overflow_test.go / ratelimit_batch_test.go.

func TestRateLimiterBasic(t *testing.T) {
	t.Run("Allow", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		for i := range 10 {
			if !rl.Allow("key") {
				t.Errorf("Allow should succeed at iteration %d", i)
			}
		}
		if rl.Allow("key") {
			t.Error("Should be rate limited after max")
		}
	})

	t.Run("AllowN", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		tests := []struct {
			n    int
			want bool
		}{
			{0, true},
			{-1, false},
			{5, true},
			{5, true},
			{1, false},
			{100, false},
		}
		for _, tt := range tests {
			if got := rl.AllowN("key", tt.n); got != tt.want {
				t.Errorf("AllowN(%d) = %v, want %v", tt.n, got, tt.want)
			}
		}
	})

	t.Run("AllowN_EmptyKey", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		if rl.AllowN("", 1) {
			t.Error("AllowN should reject empty key with n > 0")
		}
		// n=0 always returns true regardless of key
		if !rl.AllowN("", 0) {
			t.Error("AllowN with n=0 should return true")
		}
	})

	t.Run("Reset", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		for range 10 {
			rl.Allow("key")
		}
		rl.Reset("key")
		for i := range 10 {
			if !rl.Allow("key") {
				t.Errorf("Should allow after reset, failed at %d", i)
			}
		}

		// Reset non-existent key should not panic
		rl.Reset("nonexistent")
		// Reset empty key should not panic
		rl.Reset("")
	})

	t.Run("TokenRefill", func(t *testing.T) {
		rl := NewRateLimiter(10, 100*time.Millisecond)
		defer rl.Close()

		for range 10 {
			rl.Allow("key")
		}
		if rl.Allow("key") {
			t.Error("Should be rate limited")
		}
		time.Sleep(150 * time.Millisecond)
		if !rl.Allow("key") {
			t.Error("Should have tokens after refill")
		}
	})

	t.Run("ClosedOperations", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		rl.Close()

		if rl.Allow("test") {
			t.Error("Should not allow after close")
		}
		if rl.AllowN("test", 1) {
			t.Error("AllowN should not allow after close")
		}
		rl.Close() // double close should be safe
	})

	t.Run("Eviction", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		rl.mu.Lock()
		rl.maxBuckets = 5
		rl.mu.Unlock()

		for i := range 6 {
			rl.Allow(fmt.Sprintf("key-%d", i))
			time.Sleep(time.Millisecond)
		}

		rl.mu.Lock()
		size := len(rl.buckets)
		rl.mu.Unlock()
		if size > 5 {
			t.Errorf("Expected max 5 buckets, got %d", size)
		}
	})

	t.Run("ZeroParameters", func(t *testing.T) {
		// NewRateLimiter tolerates zero rate/window; construction must not panic.
		rl := NewRateLimiter(0, 0)
		rl.Close()
		rl = NewRateLimiter(100, 0)
		rl.Close()
	})
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

// TestRateLimiterStaleBucketsNotCleanedBelowCapacity verifies that stale
// buckets are not evicted while the map is below max capacity.
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

// TestAllowNRefillOverflow guards the refill arithmetic against int64
// overflow: with maxRate=1<<31 and window=16s, advancing the clock by half a
// window makes maxRate*elapsed ≈ 1.7e19 > MaxInt64, which used to wrap
// negative and permanently stall the bucket instead of refilling it.
// The limiter is constructed directly (not via Config) because this is
// exactly the "direct NewRateLimiter user" case the AllowN guard must cover
// without relying on Config bounds.
func TestAllowNRefillOverflow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rl := NewRateLimiter(1<<31, 16*time.Second)
	rl.nowFunc = func() time.Time { return now }
	defer rl.Close()

	const key = "overflow-user"
	if !rl.AllowN(key, 1<<31) {
		t.Fatal("initial burst should drain the whole bucket")
	}
	if rl.AllowN(key, 1) {
		t.Fatal("bucket must be empty right after draining")
	}

	now = now.Add(8 * time.Second) // half a window: product overflows int64
	if !rl.AllowN(key, 1) {
		t.Fatal("overflowing refill must refill the bucket, not stall it")
	}

	// The residual-time update must stay exact: tokensToAdd*window ≈ 1.7e19
	// exceeds MaxInt64, and the int64 form of the computation wrapped negative
	// and moved lastRefill backwards (observed as a past timestamp).
	if got := rl.buckets[key].lastRefill; got != now.UnixNano() {
		t.Fatalf("lastRefill = %d, want %d (residual time corrupted)", got, now.UnixNano())
	}
}

// TestRateLimiterBatchEvictionAtCapacity verifies that when the bucket map is at
// capacity, a batch of the oldest entries is evicted in a single pass (not one
// at a time), keeping the map bounded and letting new distinct keys proceed.
// This is the regression guard for the O(n)->amortized-O(log n) eviction fix.
func TestRateLimiterBatchEvictionAtCapacity(t *testing.T) {
	rl := NewRateLimiter(1000, time.Minute)
	rl.maxBuckets = 100
	// Monotonic, distinct clock so lastRefill values are strictly increasing:
	// the oldest buckets are unambiguously the earliest inserted.
	var tick int64
	rl.nowFunc = func() time.Time {
		tick++
		return time.Unix(0, tick).UTC()
	}
	defer rl.Close()

	for i := range rl.maxBuckets {
		if !rl.Allow(fmt.Sprintf("u%d", i)) {
			t.Fatalf("Allow(u%d) failed during fill", i)
		}
	}
	if got := len(rl.buckets); got != rl.maxBuckets {
		t.Fatalf("after fill: got %d buckets, want %d", got, rl.maxBuckets)
	}

	// One more distinct key triggers eviction. maxBuckets/10 == 10, so the 10
	// oldest buckets go in a single pass, then the new one is inserted: 100-10+1.
	if !rl.Allow("overflow") {
		t.Fatal("Allow(overflow) should succeed after batch eviction")
	}
	if got, want := len(rl.buckets), rl.maxBuckets-10+1; got != want {
		t.Errorf("after overflow: got %d buckets, want %d (batch should evict 10)", got, want)
	}

	// Sustained over-capacity traffic must keep the map bounded at maxBuckets.
	for i := range 5000 {
		if !rl.Allow(fmt.Sprintf("v%d", i)) {
			t.Fatalf("Allow(v%d) failed under sustained load", i)
		}
		if got := len(rl.buckets); got > rl.maxBuckets {
			t.Fatalf("map exceeded maxBuckets: got %d > %d", got, rl.maxBuckets)
		}
	}
}

// BenchmarkRateLimiterAtCapacity measures Allow() cost for distinct keys while
// the bucket map is at capacity — the eviction hot path. Before the batch fix
// this was O(n) per insert (full-map scan each time); it is now amortized
// O(log n) (one scan per ~maxBuckets/10 inserts). Allocs/op is the deterministic
// signal; ns/op varies with thermal throttling (see benchmark-thermal-variance).
func BenchmarkRateLimiterAtCapacity(b *testing.B) {
	rl := NewRateLimiter(1000, time.Minute)
	rl.maxBuckets = 10000
	defer rl.Close()
	for i := range rl.maxBuckets {
		rl.Allow(fmt.Sprintf("seed-%d", i))
	}
	b.ResetTimer()
	i := 0
	for b.Loop() {
		rl.Allow(fmt.Sprintf("k-%d", i))
		i++
	}
}

// =============================================================================
// Concurrency tests
// =============================================================================

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
