package jwt

import (
	"context"
	"sync"
	"time"
)

// RateLimiter provides rate limiting for JWT operations to prevent abuse
type RateLimiter struct {
	mu              sync.RWMutex
	buckets         map[string]*bucket
	maxRate         int           // requests per window
	window          time.Duration // time window
	cleanupInterval time.Duration // cleanup interval
	stopChan        chan struct{}
}

// bucket represents a token bucket for rate limiting
type bucket struct {
	tokens     int
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets:         make(map[string]*bucket),
		maxRate:         maxRate,
		window:          window,
		cleanupInterval: window * 2, // Cleanup old buckets every 2 windows
		stopChan:        make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request is allowed for the given key (e.g., IP address, user ID)
func (rl *RateLimiter) Allow(key string) bool {
	return rl.AllowN(key, 1)
}

// AllowN checks if N requests are allowed for the given key
func (rl *RateLimiter) AllowN(key string, n int) bool {
	rl.mu.RLock()
	b, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		if b, exists = rl.buckets[key]; !exists {
			b = &bucket{
				tokens:     rl.maxRate,
				lastRefill: time.Now(),
			}
			rl.buckets[key] = b
		}
		rl.mu.Unlock()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill)

	// Refill tokens based on elapsed time
	if elapsed >= rl.window {
		b.tokens = rl.maxRate
		b.lastRefill = now
	} else {
		// Partial refill based on elapsed time
		tokensToAdd := int(float64(rl.maxRate) * elapsed.Seconds() / rl.window.Seconds())
		b.tokens = minInt(rl.maxRate, b.tokens+tokensToAdd)
		if tokensToAdd > 0 {
			b.lastRefill = now
		}
	}

	// Check if we have enough tokens
	if b.tokens >= n {
		b.tokens -= n
		return true
	}

	return false
}

// AllowWithContext checks if a request is allowed with context support
func (rl *RateLimiter) AllowWithContext(ctx context.Context, key string) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		return rl.Allow(key)
	}
}

// Reset resets the rate limit for a specific key
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
}

// GetStats returns rate limiting statistics for a key
func (rl *RateLimiter) GetStats(key string) (tokens int, lastRefill time.Time, exists bool) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if b, ok := rl.buckets[key]; ok {
		b.mu.Lock()
		tokens = b.tokens
		lastRefill = b.lastRefill
		b.mu.Unlock()
		exists = true
	}

	return
}

// Close stops the rate limiter and cleans up resources
func (rl *RateLimiter) Close() {
	close(rl.stopChan)
	rl.mu.Lock()
	rl.buckets = nil
	rl.mu.Unlock()
}

// cleanupLoop periodically removes old buckets to prevent memory leaks
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanupOldBuckets()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanupOldBuckets removes old buckets that haven't been used recently
func (rl *RateLimiter) cleanupOldBuckets() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.cleanupInterval)

	for key, b := range rl.buckets {
		b.mu.Lock()
		if b.lastRefill.Before(cutoff) {
			delete(rl.buckets, key)
		}
		b.mu.Unlock()
	}
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SecurityRateLimiter provides pre-configured rate limiters for different security scenarios
type SecurityRateLimiter struct {
	TokenCreation   *RateLimiter
	TokenValidation *RateLimiter
	LoginAttempts   *RateLimiter
	PasswordReset   *RateLimiter
}

// NewSecurityRateLimiter creates a new security rate limiter with sensible defaults
func NewSecurityRateLimiter() *SecurityRateLimiter {
	return &SecurityRateLimiter{
		TokenCreation:   NewRateLimiter(100, time.Minute),  // 100 tokens per minute
		TokenValidation: NewRateLimiter(1000, time.Minute), // 1000 validations per minute
		LoginAttempts:   NewRateLimiter(5, time.Minute),    // 5 login attempts per minute
		PasswordReset:   NewRateLimiter(3, time.Hour),      // 3 password resets per hour
	}
}

// Close closes all rate limiters
func (srl *SecurityRateLimiter) Close() {
	if srl.TokenCreation != nil {
		srl.TokenCreation.Close()
	}
	if srl.TokenValidation != nil {
		srl.TokenValidation.Close()
	}
	if srl.LoginAttempts != nil {
		srl.LoginAttempts.Close()
	}
	if srl.PasswordReset != nil {
		srl.PasswordReset.Close()
	}
}

// RateLimitConfig provides configuration for rate limiting
type RateLimitConfig struct {
	Enabled           bool
	TokenCreationRate int           // requests per minute
	ValidationRate    int           // requests per minute
	LoginAttemptRate  int           // attempts per minute
	PasswordResetRate int           // resets per hour
	CleanupInterval   time.Duration // cleanup interval
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           true,
		TokenCreationRate: 1000,
		ValidationRate:    10000,
		LoginAttemptRate:  10,
		PasswordResetRate: 5,
		CleanupInterval:   5 * time.Minute,
	}
}

// NewSecurityRateLimiterWithConfig creates a security rate limiter with custom configuration
func NewSecurityRateLimiterWithConfig(config RateLimitConfig) *SecurityRateLimiter {
	if !config.Enabled {
		return &SecurityRateLimiter{} // Return empty limiters (no limiting)
	}

	return &SecurityRateLimiter{
		TokenCreation:   NewRateLimiter(config.TokenCreationRate, time.Minute),
		TokenValidation: NewRateLimiter(config.ValidationRate, time.Minute),
		LoginAttempts:   NewRateLimiter(config.LoginAttemptRate, time.Minute),
		PasswordReset:   NewRateLimiter(config.PasswordResetRate, time.Hour),
	}
}

// IsRateLimited checks if an operation is rate limited
func (srl *SecurityRateLimiter) IsRateLimited(operation, key string) bool {
	if srl == nil {
		return false // No rate limiting if not configured
	}

	switch operation {
	case "token_creation":
		return srl.TokenCreation != nil && !srl.TokenCreation.Allow(key)
	case "token_validation":
		return srl.TokenValidation != nil && !srl.TokenValidation.Allow(key)
	case "login_attempt":
		return srl.LoginAttempts != nil && !srl.LoginAttempts.Allow(key)
	case "password_reset":
		return srl.PasswordReset != nil && !srl.PasswordReset.Allow(key)
	default:
		return false
	}
}
