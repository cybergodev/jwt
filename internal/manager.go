package internal

import (
	"fmt"
	"time"
)

type tokenClaims struct {
	ID        string `json:"jti,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

type Manager struct {
	store Store
}

func NewManager(store Store) *Manager {
	return &Manager{store: store}
}

func (m *Manager) BlacklistToken(tokenID string, expiresAt time.Time) error {
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

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if claims.ExpiresAt > 0 {
		expiresAt = time.Unix(claims.ExpiresAt, 0)
	}

	return m.BlacklistToken(claims.ID, expiresAt)
}

func (m *Manager) Close() error {
	return m.store.Close()
}
