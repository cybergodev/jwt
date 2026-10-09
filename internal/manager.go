package internal

import (
	"fmt"
	"time"
)

// DefaultBlacklistTTL is the default time-to-live for blacklisted tokens
// when the token does not have an expiration time.
const DefaultBlacklistTTL = 7 * 24 * time.Hour

// MaxBlacklistTTL caps the maximum blacklist entry TTL to prevent
// untrusted exp values from crafted tokens causing DoS.
const MaxBlacklistTTL = 30 * 24 * time.Hour

// storeOps defines the storage operations Manager needs from a blacklist
// store; it is the internal mirror of the public jwt.BlacklistStore
// interface. Cleanup is deliberately absent: Manager never triggers it —
// the built-in memoryStore schedules its own, and custom stores own their
// lifecycle via Close.
type storeOps interface {
	Add(tokenID string, expiresAt time.Time) error
	Contains(tokenID string) (bool, error)
	Close() error
}

// Manager handles token blacklist operations.
type Manager struct {
	store   storeOps
	nowFunc func() time.Time
}

// NewManagerWithClock creates a new Manager with the given store and clock function.
// If nowFunc is nil, time.Now is used.
func NewManagerWithClock(s storeOps, nowFunc func() time.Time) *Manager {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &Manager{store: s, nowFunc: nowFunc}
}

func (m *Manager) blacklistToken(tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}
	return m.store.Add(tokenID, expiresAt)
}

func (m *Manager) IsBlacklisted(tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}
	return m.store.Contains(tokenID)
}

// BlacklistVerified adds a pre-verified token ID to the blacklist.
// Callers MUST verify the token's signature before calling this; accepting an
// unverified token ID would let forged tokens pollute the blacklist.
func (m *Manager) BlacklistVerified(tokenID string, expiresAt time.Time) error {
	// The empty-token-ID guard lives in blacklistToken, the single choke point
	// in front of the store.
	//
	// nowFunc may return a moving value (SystemClock); capture once so the
	// default and max bounds are computed from the same instant.
	now := m.nowFunc()
	blacklistExpiry := now.Add(DefaultBlacklistTTL)
	if !expiresAt.IsZero() && expiresAt.After(blacklistExpiry) {
		maxExp := now.Add(MaxBlacklistTTL)
		if expiresAt.After(maxExp) {
			blacklistExpiry = maxExp
		} else {
			blacklistExpiry = expiresAt
		}
	}

	return m.blacklistToken(tokenID, blacklistExpiry)
}

func (m *Manager) Close() error {
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}
