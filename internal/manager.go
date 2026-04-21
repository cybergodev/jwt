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

type tokenClaims struct {
	ID        string `json:"jti,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// storeOps defines the storage operations needed by Manager.
// This is a subset of Store that excludes Cleanup(), since Manager
// never triggers cleanup — the built-in memoryStore handles that internally.
// The subset also matches the public jwt.BlacklistStore interface.
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

// ParseTokenID extracts the token ID (jti) from a JWT without verifying the signature.
// Returns empty string if the token has no jti claim.
func ParseTokenID(tokenString string) (string, error) {
	claims, err := parseTokenClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.ID, nil
}

// parseTokenClaims extracts token claims without verification.
func parseTokenClaims(tokenString string) (*tokenClaims, error) {
	claims := &tokenClaims{}
	_, _, err := ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	return claims, nil
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

func (m *Manager) BlacklistTokenString(tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	claims, err := parseTokenClaims(tokenString)
	if err != nil {
		return err
	}

	if claims.ID == "" {
		return fmt.Errorf("token does not contain a valid ID (jti)")
	}

	expiresAt := m.nowFunc().Add(DefaultBlacklistTTL)
	if claims.ExpiresAt > 0 {
		tokenExp := time.Unix(claims.ExpiresAt, 0)
		if tokenExp.After(expiresAt) {
			maxExp := m.nowFunc().Add(MaxBlacklistTTL)
			if tokenExp.After(maxExp) {
				expiresAt = maxExp
			} else {
				expiresAt = tokenExp
			}
		}
	}

	return m.blacklistToken(claims.ID, expiresAt)
}

func (m *Manager) Close() error {
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}
