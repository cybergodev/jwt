package jwt

import (
	"time"
)

// BlacklistConfig represents blacklist configuration
type BlacklistConfig struct {
	CleanupInterval   time.Duration `json:"cleanup_interval"`
	MaxSize           int           `json:"max_size"`
	EnableAutoCleanup bool          `json:"enable_auto_cleanup"`
	StoreType         string        `json:"store_type"`
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
