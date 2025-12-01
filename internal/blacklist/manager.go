package blacklist

import (
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal/core"
)

// Manager wraps a Store and provides high-level token blacklist operations.
// It handles token parsing and expiration management.
type Manager struct {
	store Store
}

// NewManager creates a new blacklist manager with the given store
func NewManager(store Store) *Manager {
	return &Manager{store: store}
}

// BlacklistToken adds a token to the blacklist
func (m *Manager) BlacklistToken(tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}
	return m.store.Add(tokenID, expiresAt)
}

// IsBlacklisted checks if a token is blacklisted
func (m *Manager) IsBlacklisted(tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}
	return m.store.Contains(tokenID)
}

// BlacklistTokenString extracts token ID from token string and blacklists it
func (m *Manager) BlacklistTokenString(tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	type minimalClaims struct {
		ID        string `json:"jti,omitempty"`
		ExpiresAt int64  `json:"exp,omitempty"`
	}

	claims := &minimalClaims{}

	_, _, err := core.ParseUnverified(tokenString, claims)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if claims.ID == "" {
		return fmt.Errorf("token does not contain a valid ID (jti)")
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if claims.ExpiresAt > 0 {
		expiresAt = time.Unix(claims.ExpiresAt, 0)
	}

	return m.BlacklistToken(claims.ID, expiresAt)
}

// Close closes the manager and underlying store
func (m *Manager) Close() error {
	return m.store.Close()
}
