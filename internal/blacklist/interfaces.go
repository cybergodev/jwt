package blacklist

import (
	"time"
)

// Store defines the interface for blacklist storage implementations.
// Implementations must be thread-safe for concurrent use.
type Store interface {
	// Add adds a token to the blacklist with expiration time
	Add(tokenID string, expiresAt time.Time) error

	// Contains checks if a token is in the blacklist and not expired
	Contains(tokenID string) (bool, error)

	// Cleanup removes expired tokens and returns the count removed
	Cleanup() (int, error)

	// Close closes the store and releases all resources
	Close() error
}

// Config represents blacklist configuration
type Config struct {
	CleanupInterval   time.Duration `json:"cleanup_interval"`
	MaxSize           int           `json:"max_size"`
	EnableAutoCleanup bool          `json:"enable_auto_cleanup"`
}

// NewStore creates a new store based on the configuration
func NewStore(config Config) Store {
	return NewMemoryStore(config.MaxSize, config.CleanupInterval, config.EnableAutoCleanup)
}
