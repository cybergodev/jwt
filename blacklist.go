package jwt

import (
	"time"
)

// BlacklistConfig represents blacklist configuration
type BlacklistConfig struct {
	// CleanupInterval defines how often to run cleanup of expired tokens
	CleanupInterval time.Duration `json:"cleanup_interval"`

	// MaxSize defines the maximum number of tokens to keep in memory
	MaxSize int `json:"max_size"`

	// EnableAutoCleanup enables automatic cleanup of expired tokens
	EnableAutoCleanup bool `json:"enable_auto_cleanup"`

	// StoreType defines the storage backend type
	StoreType string `json:"store_type"`
}

// DefaultBlacklistConfig returns a default blacklist configuration
func DefaultBlacklistConfig() BlacklistConfig {
	return BlacklistConfig{
		CleanupInterval:   5 * time.Minute,
		MaxSize:           100000,
		EnableAutoCleanup: true,
		StoreType:         "memory",
	}
}
