package jwt

import (
	"sync"
	"time"
)

// RateLimiter provides rate limiting for JWT operations using token bucket algorithm.
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
		nowFunc:    time.Now,
	}
}

// Allow checks if a single request is allowed for the given key.
func (rl *RateLimiter) Allow(key string) bool {
	return rl.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key.
func (rl *RateLimiter) AllowN(key string, n int) bool {
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
			rl.evictOldestUnsafe()
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
		tokensToAdd := int((int64(rl.maxRate) * elapsed) / windowNano)
		if tokensToAdd > 0 {
			b.tokens += tokensToAdd
			if b.tokens > rl.maxRate {
				b.tokens = rl.maxRate
			}
			// Preserve residual time instead of resetting
			consumedNano := (int64(tokensToAdd) * windowNano) / int64(rl.maxRate)
			b.lastRefill += consumedNano
		}
	}

	if b.tokens >= n {
		b.tokens -= n
		return true
	}

	return false
}

// Reset removes the rate limit bucket for the given key.
func (rl *RateLimiter) Reset(key string) {
	if key == "" {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
}

// Close closes the rate limiter and releases all resources.
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

	var oldestKey string
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
