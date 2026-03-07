package internal

import (
	"fmt"
	"time"
)

// DefaultBlacklistTTL is the default time-to-live for blacklisted tokens
// when the token does not have an expiration time.
const DefaultBlacklistTTL = 7 * 24 * time.Hour

type tokenClaims struct {
	ID        string `json:"jti,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// Manager handles token blacklist operations.
// It uses function fields instead of an interface to allow
// flexible implementation injection without requiring an adapter.
type Manager struct {
	addFunc      func(tokenID string, expiresAt time.Time) error
	containsFunc func(tokenID string) (bool, error)
	closeFunc    func() error
}

// NewManager creates a new Manager with the given store functions.
// Both add and contains functions must be non-nil.
func NewManager(add func(tokenID string, expiresAt time.Time) error, contains func(tokenID string) (bool, error), close func() error) *Manager {
	// Ensure required functions are provided
	if add == nil {
		add = func(string, time.Time) error { return fmt.Errorf("blacklist store not configured") }
	}
	if contains == nil {
		contains = func(string) (bool, error) { return false, fmt.Errorf("blacklist store not configured") }
	}

	return &Manager{
		addFunc:      add,
		containsFunc: contains,
		closeFunc:    close,
	}
}

func (m *Manager) BlacklistToken(tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}
	return m.addFunc(tokenID, expiresAt)
}

func (m *Manager) IsBlacklisted(tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}
	return m.containsFunc(tokenID)
}

func (m *Manager) BlacklistTokenString(tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	claims := &tokenClaims{}
	_, _, err := ParseUnverified(tokenString, claims)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if claims.ID == "" {
		return fmt.Errorf("token does not contain a valid ID (jti)")
	}

	// Use token's expiration time, or default to DefaultBlacklistTTL
	expiresAt := time.Now().Add(DefaultBlacklistTTL)
	if claims.ExpiresAt > 0 {
		expiresAt = time.Unix(claims.ExpiresAt, 0)
	}

	return m.BlacklistToken(claims.ID, expiresAt)
}

func (m *Manager) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}
