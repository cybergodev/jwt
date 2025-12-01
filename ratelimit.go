package jwt

import (
	"sync"
	"time"
)

// RateLimiter provides rate limiting for JWT operations to prevent abuse.
// It uses a token bucket algorithm with per-key rate limiting.
// The rate limiter is thread-safe and can be used concurrently.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	maxRate    int
	window     time.Duration
	maxBuckets int
	closed     bool
}

// bucket represents a token bucket for rate limiting
type bucket struct {
	tokens     int
	lastRefill int64
}

// NewRateLimiter creates a new rate limiter with the specified rate and window.
// maxRate is the maximum number of requests allowed per window.
// window is the time window for rate limiting (e.g., time.Minute).
// If maxRate or window is invalid, sensible defaults are used.
func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter {
	if maxRate <= 0 {
		maxRate = 100
	}
	if window <= 0 {
		window = time.Minute
	}

	return &RateLimiter{
		buckets:    make(map[string]*bucket),
		maxRate:    maxRate,
		window:     window,
		maxBuckets: 10000,
	}
}

// Allow checks if a single request is allowed for the given key.
// Returns true if the request is allowed, false if rate limit is exceeded.
// An empty key always returns false.
func (rl *RateLimiter) Allow(key string) bool {
	return rl.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key.
// Returns true if all n requests are allowed, false if rate limit would be exceeded.
// An empty key always returns false. n <= 0 always returns true.
func (rl *RateLimiter) AllowN(key string, n int) bool {
	if n <= 0 {
		return true
	}
	if key == "" {
		return false
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.closed {
		return false
	}

	nowNano := time.Now().UnixNano()
	b, exists := rl.buckets[key]

	if !exists {
		if n > rl.maxRate {
			return false
		}
		if len(rl.buckets) >= rl.maxBuckets {
			rl.evictOldestUnsafe()
		}
		rl.buckets[key] = &bucket{
			tokens:     rl.maxRate - n,
			lastRefill: nowNano,
		}
		return true
	}

	elapsed := nowNano - b.lastRefill

	if elapsed >= int64(rl.window) {
		b.tokens = rl.maxRate
		b.lastRefill = nowNano
	} else if elapsed > 0 {
		tokensToAdd := int(float64(rl.maxRate) * float64(elapsed) / float64(rl.window))
		if tokensToAdd > 0 {
			b.tokens += tokensToAdd
			if b.tokens > rl.maxRate {
				b.tokens = rl.maxRate
			}
			b.lastRefill = nowNano
		}
	}

	if b.tokens >= n {
		b.tokens -= n
		return true
	}

	return false
}

// Reset removes the rate limit bucket for the given key, effectively resetting its rate limit.
// This is useful for clearing rate limits after successful authentication or for testing.
func (rl *RateLimiter) Reset(key string) {
	if key == "" {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
}

// Close closes the rate limiter and releases all resources.
// After calling Close, all subsequent Allow/AllowN calls will return false.
// It is safe to call Close multiple times.
func (rl *RateLimiter) Close() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.closed {
		return
	}

	rl.closed = true
	clear(rl.buckets)
	rl.buckets = nil
}

func (rl *RateLimiter) evictOldestUnsafe() {
	if len(rl.buckets) == 0 {
		return
	}

	oldestKey := ""
	oldestTime := int64(1<<63 - 1)

	for key, b := range rl.buckets {
		if b.lastRefill < oldestTime {
			oldestKey = key
			oldestTime = b.lastRefill
		}
	}

	if oldestKey != "" {
		delete(rl.buckets, oldestKey)
	}
}
