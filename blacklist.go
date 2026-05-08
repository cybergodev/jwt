package jwt

import (
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// BlacklistStore defines the interface for token blacklist storage backends.
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Example implementation:
//
//	type RedisStore struct {
//	    client *redis.Client
//	}
//
//	func (s *RedisStore) Add(tokenID string, expiresAt time.Time) error {
//	    return s.client.Set(ctx, "blacklist:"+tokenID, "1", time.Until(expiresAt)).Err()
//	}
type BlacklistStore interface {
	// Add adds a token ID to the blacklist with the given expiration time.
	// Returns an error if the operation fails.
	Add(tokenID string, expiresAt time.Time) error

	// Contains checks if a token ID exists in the blacklist and has not expired.
	// Returns false if the token is not blacklisted or has expired.
	Contains(tokenID string) (bool, error)

	// Close releases any resources used by the store.
	// After Close is called, all other methods should return errors.
	Close() error
}

// BlacklistConfig configures the token blacklist behavior.
type BlacklistConfig struct {
	// CleanupInterval specifies how often expired tokens are removed.
	// Only used when EnableAutoCleanup is true and Store is nil.
	CleanupInterval time.Duration

	// MaxSize is the maximum number of tokens in the in-memory store.
	// Only used when Store is nil.
	MaxSize int

	// EnableAutoCleanup enables automatic removal of expired tokens.
	// Only used when Store is nil. For the built-in store, auto-cleanup is
	// always enabled regardless of this value to prevent unbounded memory growth.
	// This field only takes effect when using a custom BlacklistStore.
	EnableAutoCleanup bool

	// Store is an optional custom blacklist storage backend.
	// If provided, CleanupInterval, MaxSize, and EnableAutoCleanup are ignored.
	// The store must implement the BlacklistStore interface.
	Store BlacklistStore

	// clock is set internally from Config.Clock to maintain testability.
	// When nil, time.Now is used (default behavior).
	clock func() time.Time
}

// DefaultBlacklistConfig returns a BlacklistConfig with sensible defaults.
func DefaultBlacklistConfig() BlacklistConfig {
	return BlacklistConfig{
		CleanupInterval:   5 * time.Minute,
		MaxSize:           100000,
		EnableAutoCleanup: true,
	}
}

// validate validates the blacklist configuration.
// Returns an error if the configuration is invalid.
func (c *BlacklistConfig) validate() error {
	// Skip validation if custom store is provided
	if c.Store != nil {
		return nil
	}
	if c.MaxSize <= 0 {
		return fmt.Errorf("blacklist max size must be positive")
	}
	if c.CleanupInterval <= 0 {
		return fmt.Errorf("blacklist cleanup interval must be positive")
	}
	return nil
}

// createManager creates a Manager with the appropriate store based on the configuration.
func (c *BlacklistConfig) createManager() *internal.Manager {
	if c.Store != nil {
		return internal.NewManagerWithClock(c.Store, c.clock)
	}
	store := internal.NewMemoryStore(
		c.MaxSize,
		c.CleanupInterval,
		c.EnableAutoCleanup,
		c.clock,
	)
	return internal.NewManagerWithClock(store, c.clock)
}
