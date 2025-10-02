package blacklist

import (
	"errors"
	"runtime"
	"sort"
	"sync"
	"time"
)

// errStoreClosed indicates that the store has been closed
var errStoreClosed = errors.New("blacklist store is closed")

// tokenEntry represents a blacklisted token with its expiration time
type tokenEntry struct {
	tokenID   string
	expiresAt time.Time
}

// memoryStore implements the Store interface using in-memory storage
type memoryStore struct {
	// tokens maps token ID to expiration time for O(1) lookup
	tokens map[string]time.Time

	// expirationQueue maintains tokens sorted by expiration time for efficient cleanup
	// Using a simple slice for now, could be optimized with a heap for very large datasets
	expirationQueue []tokenEntry

	mu      sync.RWMutex
	maxSize int
	closed  bool
}

// NewMemoryStore creates a new in-memory blacklist store
func NewMemoryStore(maxSize int) Store {
	return &memoryStore{
		tokens:          make(map[string]time.Time, maxSize/2), // Pre-allocate with higher capacity
		expirationQueue: make([]tokenEntry, 0, maxSize/2),
		maxSize:         maxSize,
	}
}

// Add adds a token to the blacklist with expiration time
func (m *memoryStore) Add(tokenID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errStoreClosed
	}

	// Check if we're at capacity and need to make room
	if len(m.tokens) >= m.maxSize {
		m.cleanupExpiredUnsafe(time.Now())

		if len(m.tokens) >= m.maxSize {
			m.evictOldestUnsafe(m.maxSize / 10)
		}
	}

	// Check if token already exists to avoid duplicate queue entries
	_, exists := m.tokens[tokenID]
	m.tokens[tokenID] = expiresAt

	// Only add to queue if it's a new token
	if !exists {
		m.expirationQueue = append(m.expirationQueue, tokenEntry{
			tokenID:   tokenID,
			expiresAt: expiresAt,
		})
	}

	return nil
}

// Contains checks if a token is in the blacklist
func (m *memoryStore) Contains(tokenID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, errStoreClosed
	}

	expiresAt, exists := m.tokens[tokenID]
	if !exists {
		return false, nil
	}

	// Check if token has expired
	if time.Now().After(expiresAt) {
		// Token has expired, but we'll let the cleanup process handle removal
		// to avoid write locks during read operations
		return false, nil
	}

	return true, nil
}

// Remove removes a token from the blacklist
func (m *memoryStore) Remove(tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errStoreClosed
	}

	delete(m.tokens, tokenID)

	// Note: We don't remove from expirationQueue immediately for performance reasons
	// The cleanup process will handle stale entries

	return nil
}

// Cleanup removes expired tokens from the blacklist
func (m *memoryStore) Cleanup() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, errStoreClosed
	}

	now := time.Now()
	return m.cleanupExpiredUnsafe(now), nil
}

// Size returns the current number of tokens in the blacklist
func (m *memoryStore) Size() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return 0, errStoreClosed
	}

	return len(m.tokens), nil
}

// Close closes the store and releases resources
func (m *memoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// Clear all data to help GC
	m.tokens = nil
	m.expirationQueue = nil

	return nil
}

// cleanupExpiredUnsafe removes expired tokens (must be called with write lock held)
func (m *memoryStore) cleanupExpiredUnsafe(now time.Time) int {
	cleaned := 0

	// Clean up expired tokens from the main map
	for tokenID, expiresAt := range m.tokens {
		if now.After(expiresAt) {
			delete(m.tokens, tokenID)
			cleaned++
		}
	}

	// Clean up the expiration queue
	validEntries := make([]tokenEntry, 0, len(m.expirationQueue))
	for _, entry := range m.expirationQueue {
		// Keep entries that are not expired and still exist in the main map
		if expiresAt, exists := m.tokens[entry.tokenID]; exists && !now.After(expiresAt) {
			validEntries = append(validEntries, entry)
		}
	}

	m.expirationQueue = validEntries

	// Let Go's GC handle memory cleanup automatically
	// Forcing GC is an anti-pattern that degrades performance
	_ = runtime.NumGoroutine()

	return cleaned
}

// evictOldestUnsafe removes the oldest tokens to make room (must be called with write lock held)
func (m *memoryStore) evictOldestUnsafe(count int) {
	if len(m.tokens) == 0 {
		return
	}

	type tokenAge struct {
		tokenID   string
		expiresAt time.Time
	}

	validTokens := make([]tokenAge, 0, len(m.tokens))
	for tokenID, expiresAt := range m.tokens {
		validTokens = append(validTokens, tokenAge{tokenID, expiresAt})
	}

	sort.Slice(validTokens, func(i, j int) bool {
		return validTokens[i].expiresAt.Before(validTokens[j].expiresAt)
	})

	evicted := 0
	for i := 0; i < len(validTokens) && evicted < count; i++ {
		delete(m.tokens, validTokens[i].tokenID)
		evicted++
	}

	m.expirationQueue = make([]tokenEntry, 0, len(m.tokens))
	for tokenID, expiresAt := range m.tokens {
		m.expirationQueue = append(m.expirationQueue, tokenEntry{
			tokenID:   tokenID,
			expiresAt: expiresAt,
		})
	}
}
