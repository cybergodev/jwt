package blacklist

import (
	"time"
)

// Store defines the interface for blacklist storage implementations
type Store interface {
	// Add adds a token to the blacklist with expiration time
	Add(tokenID string, expiresAt time.Time) error

	// Contains checks if a token is in the blacklist
	Contains(tokenID string) (bool, error)

	// Remove removes a token from the blacklist (optional, for manual cleanup)
	Remove(tokenID string) error

	// Cleanup removes expired tokens from the blacklist
	Cleanup() (int, error)

	// Size returns the current number of tokens in the blacklist
	Size() (int, error)

	// Close closes the store and releases resources
	Close() error
}

// Manager manages the blacklist operations and integrates with JWT processing
type Manager interface {
	// BlacklistToken adds a token to the blacklist
	BlacklistToken(tokenID string, expiresAt time.Time) error

	// IsBlacklisted checks if a token is blacklisted
	IsBlacklisted(tokenID string) (bool, error)

	// BlacklistTokenString extracts token ID from token string and blacklists it
	BlacklistTokenString(tokenString string) error

	// Close closes the manager and underlying store
	Close() error
}

// Stats represents blacklist statistics
type Stats struct {
	TotalTokens    int           `json:"total_tokens"`
	ExpiredTokens  int           `json:"expired_tokens"`
	CleanupCount   int           `json:"cleanup_count"`
	LastCleanup    time.Time     `json:"last_cleanup"`
	MemoryUsage    int64         `json:"memory_usage_bytes"`
	HitRate        float64       `json:"hit_rate"`
	MissRate       float64       `json:"miss_rate"`
	AverageLatency time.Duration `json:"average_latency"`
}

// Config represents blacklist configuration
type Config struct {
	// CleanupInterval defines how often to run cleanup of expired tokens
	CleanupInterval time.Duration `json:"cleanup_interval"`

	// MaxSize defines the maximum number of tokens to keep in memory
	MaxSize int `json:"max_size"`

	// EnableMetrics enables collection of performance metrics
	EnableMetrics bool `json:"enable_metrics"`

	// EnableAutoCleanup enables automatic cleanup of expired tokens
	EnableAutoCleanup bool `json:"enable_auto_cleanup"`

	// StoreType defines the storage backend type
	StoreType string `json:"store_type"`
}

// NewStore creates a new store based on the configuration
func NewStore(config Config) Store {
	return NewMemoryStore(config.MaxSize)
}
