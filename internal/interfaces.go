package internal

import (
	"time"
)

type Store interface {
	Add(tokenID string, expiresAt time.Time) error
	Contains(tokenID string) (bool, error)
	Cleanup() (int, error)
	Close() error
}
