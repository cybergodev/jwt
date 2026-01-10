package jwt

import (
	"time"
)

type BlacklistConfig struct {
	CleanupInterval   time.Duration
	MaxSize           int
	EnableAutoCleanup bool
}

func DefaultBlacklistConfig() BlacklistConfig {
	return BlacklistConfig{
		CleanupInterval:   5 * time.Minute,
		MaxSize:           100000,
		EnableAutoCleanup: true,
	}
}
