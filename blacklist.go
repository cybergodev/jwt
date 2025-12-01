package jwt

import (
	"time"
)

// BlacklistConfig represents blacklist configuration for token revocation management
type BlacklistConfig struct {
	// CleanupInterval specifies how often expired tokens are removed from the blacklist
	CleanupInterval time.Duration

	// MaxSize defines the maximum number of tokens that can be stored in the blacklist
	MaxSize int

	// EnableAutoCleanup enables automatic cleanup of expired tokens
	EnableAutoCleanup bool
}

// DefaultBlacklistConfig returns a secure default blacklist configuration for production use
func DefaultBlacklistConfig() BlacklistConfig {
	return BlacklistConfig{
		CleanupInterval:   5 * time.Minute,
		MaxSize:           100000,
		EnableAutoCleanup: true,
	}
}
