package blacklist

import (
	"fmt"
	"sync"
	"time"

	"github.com/cybergodev/jwt/internal/core"
)

// manager implements the Manager interface
type manager struct {
	store  Store
	config Config
	mu     sync.RWMutex

	// Cleanup management
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	cleanupWg     sync.WaitGroup

	closed bool
}

// NewManager creates a new blacklist manager with the specified store and config
func NewManager(store Store, config Config) Manager {
	m := &manager{
		store:       store,
		config:      config,
		stopCleanup: make(chan struct{}),
	}

	// Start automatic cleanup if enabled
	if config.EnableAutoCleanup {
		m.startAutoCleanup()
	}

	return m
}

// BlacklistToken adds a token to the blacklist
func (m *manager) BlacklistToken(tokenID string, expiresAt time.Time) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return fmt.Errorf("blacklist manager is closed")
	}

	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}

	return m.store.Add(tokenID, expiresAt)
}

// IsBlacklisted checks if a token is blacklisted
func (m *manager) IsBlacklisted(tokenID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, fmt.Errorf("blacklist manager is closed")
	}

	if tokenID == "" {
		return false, nil
	}

	return m.store.Contains(tokenID)
}

// BlacklistTokenString extracts token ID from token string and blacklists it
func (m *manager) BlacklistTokenString(tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	// Parse the token to extract the token ID and expiration
	token, _, err := core.ParseUnverified(tokenString, &struct {
		ID        string `json:"jti,omitempty"`
		ExpiresAt int64  `json:"exp,omitempty"`
	}{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*struct {
		ID        string `json:"jti,omitempty"`
		ExpiresAt int64  `json:"exp,omitempty"`
	})
	if !ok {
		return fmt.Errorf("invalid claims type")
	}

	if claims.ID == "" {
		return fmt.Errorf("token does not contain a valid ID (jti)")
	}

	// Convert Unix timestamp to time.Time
	var expiresAt time.Time
	if claims.ExpiresAt > 0 {
		expiresAt = time.Unix(claims.ExpiresAt, 0)
	} else {
		// If no expiration, set a default expiration (24 hours from now)
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	return m.BlacklistToken(claims.ID, expiresAt)
}

// Close closes the manager and underlying store
func (m *manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// Stop cleanup goroutine
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.stopCleanup)
		m.cleanupWg.Wait()
	}

	// Close the store
	return m.store.Close()
}

// startAutoCleanup starts the automatic cleanup goroutine
func (m *manager) startAutoCleanup() {
	m.cleanupTicker = time.NewTicker(m.config.CleanupInterval)
	m.cleanupWg.Add(1)

	go func() {
		defer m.cleanupWg.Done()

		for {
			select {
			case <-m.cleanupTicker.C:
				m.performCleanup()
			case <-m.stopCleanup:
				return
			}
		}
	}()
}

// performCleanup performs cleanup of expired tokens
func (m *manager) performCleanup() {
	_, err := m.store.Cleanup()
	if err != nil {
		// Log error but don't stop the cleanup process
		return
	}
}
