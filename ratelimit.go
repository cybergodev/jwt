package jwt

import (
	"cmp"
	"math/bits"
	"slices"
	"sync"
	"time"
)

// RateLimiter provides rate limiting for JWT operations using token bucket algorithm.
// All methods are nil-receiver safe: Allow/AllowN on a nil limiter deny the
// request (fail-closed), Reset and Close are no-ops. A typed-nil *RateLimiter
// injected through Config.RateLimiter is therefore rejected per request rather
// than panicking inside the Processor.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	maxRate    int
	window     time.Duration
	maxBuckets int
	closed     bool
	nowFunc    func() time.Time
}

type bucket struct {
	tokens     int
	lastRefill int64
}

// NewRateLimiter creates a new rate limiter with the specified rate and window.
// If maxRate <= 0, defaults to 100. If window <= 0, defaults to 1 minute.
//
// Most callers do not need this constructor: to rate-limit token creation,
// set Config.EnableRateLimit (with Config.RateLimitRate and
// Config.RateLimitWindow) and the Processor builds its limiter internally.
// Use NewRateLimiter directly only for a standalone limiter or to inject a
// pre-configured one via Config.RateLimiter — note that Processor.Close
// closes an injected limiter.
func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter {
	if maxRate <= 0 {
		maxRate = 100
	}
	if window <= 0 {
		window = time.Minute
	}

	return &RateLimiter{
		buckets:    make(map[string]*bucket, 16),
		maxRate:    maxRate,
		window:     window,
		maxBuckets: 10000,
		nowFunc:    time.Now,
	}
}

// Allow checks if a single request is allowed for the given key.
func (rl *RateLimiter) Allow(key string) bool {
	return rl.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key.
// Returns false if n is negative, exceeds the configured max rate, or the rate limit
// has been exceeded. An empty key always returns false.
// A nil limiter denies the request (fail-closed) instead of panicking.
func (rl *RateLimiter) AllowN(key string, n int) bool {
	if rl == nil {
		return false
	}
	if n < 0 {
		return false
	}
	if n == 0 {
		return true
	}
	if key == "" {
		return false
	}

	// Early rejection if request exceeds max rate
	if n > rl.maxRate {
		return false
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.closed {
		return false
	}

	nowNano := rl.nowFunc().UnixNano()
	b, exists := rl.buckets[key]

	if !exists {
		if len(rl.buckets) >= rl.maxBuckets {
			rl.evictExpiredUnsafe(nowNano)
			if len(rl.buckets) >= rl.maxBuckets {
				// Batch-evict the oldest ~10% (at least 1) so the full map is not
				// scanned on every insert while at capacity. Mirrors the blacklist
				// store's eviction strategy and amortizes the O(n) scan across
				// many inserts rather than paying it per insert.
				rl.evictOldestUnsafe(max(rl.maxBuckets/10, 1))
			}
		}
		rl.buckets[key] = &bucket{
			tokens:     rl.maxRate - n,
			lastRefill: nowNano,
		}
		return true
	}

	elapsed := nowNano - b.lastRefill
	windowNano := int64(rl.window)

	if elapsed >= windowNano {
		b.tokens = rl.maxRate
		b.lastRefill = nowNano
	} else if elapsed > 0 {
		// Overflow guard: the int64 product maxRate*elapsed wraps negative for
		// extreme (rate, window) configurations (e.g. rate=1<<31 with a 16s
		// window), which permanently stalled the bucket. Compute in uint64 —
		// products up to 2^64 are exact — and treat a 128-bit overflow as a
		// full refill, matching the elapsed >= window branch above.
		hi, lo := bits.Mul64(uint64(rl.maxRate), uint64(elapsed))
		if hi != 0 {
			b.tokens = rl.maxRate
			b.lastRefill = nowNano
		} else {
			tokensToAdd := int(lo / uint64(windowNano))
			if tokensToAdd > 0 {
				b.tokens += tokensToAdd
				if b.tokens > rl.maxRate {
					b.tokens = rl.maxRate
				}
				// Preserve residual time instead of resetting. All math in
				// uint64: floor(tokensToAdd*window) ≤ maxRate*elapsed < 2^64
				// in this branch, and the quotient ≤ elapsed, so it fits int64.
				// (The int64 form wrapped negative when maxRate*elapsed fell
				// between 2^63 and 2^64, moving lastRefill backwards.)
				consumedNano := int64((uint64(tokensToAdd) * uint64(windowNano)) / uint64(rl.maxRate))
				b.lastRefill += consumedNano
			}
		}
	}

	if b.tokens >= n {
		b.tokens -= n
		return true
	}

	return false
}

// Reset removes the rate limit bucket for the given key.
// A nil limiter is a no-op.
func (rl *RateLimiter) Reset(key string) {
	if rl == nil {
		return
	}
	if key == "" {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
}

// Close closes the rate limiter and releases all resources.
// A nil limiter is a no-op.
func (rl *RateLimiter) Close() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.closed {
		return
	}

	rl.closed = true
	clear(rl.buckets)
	rl.buckets = nil
}

// evictExpiredUnsafe removes all buckets whose last activity is older than
// 2x the window duration, indicating they are stale and unlikely to be used again.
func (rl *RateLimiter) evictExpiredUnsafe(nowNano int64) {
	staleThreshold := nowNano - int64(rl.window)*2
	for key, b := range rl.buckets {
		if b.lastRefill < staleThreshold {
			delete(rl.buckets, key)
		}
	}
}

// evictOldestUnsafe removes the count buckets with the oldest lastRefill in a
// single pass. Evicting a batch (rather than one at a time) amortizes the O(n)
// scan: at capacity this makes room for ~10% of maxBuckets inserts before the
// next scan, turning per-insert eviction from O(n) into amortized O(log n).
func (rl *RateLimiter) evictOldestUnsafe(count int) {
	bucketsLen := len(rl.buckets)
	if bucketsLen == 0 || count <= 0 {
		return
	}
	if count > bucketsLen {
		count = bucketsLen
	}

	type entry struct {
		key string
		ts  int64
	}
	entries := make([]entry, 0, bucketsLen)
	for key, b := range rl.buckets {
		entries = append(entries, entry{key, b.lastRefill})
	}
	slices.SortFunc(entries, func(a, b entry) int {
		return cmp.Compare(a.ts, b.ts)
	})
	for i := 0; i < count; i++ {
		delete(rl.buckets, entries[i].key)
	}
}
