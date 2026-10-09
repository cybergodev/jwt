package internal

import (
	"errors"
	"slices"
	"sync"
	"time"
)

// ErrStoreClosed indicates that an operation was attempted on a closed store.
var ErrStoreClosed = errors.New("blacklist store is closed")

// mapCapacity returns a small initial map capacity hint to reduce early rehashing
// without wasting memory at processor creation time.
func mapCapacity(maxSize int) int {
	if maxSize <= 0 {
		return 8
	}
	if maxSize < 8 {
		return maxSize
	}
	return min(maxSize, 64)
}

// memoryStore is the built-in in-process blacklist store underlying
// NewMemoryStore; see there for sizing and cleanup semantics.
type memoryStore struct {
	tokens        map[string]time.Time
	mu            sync.RWMutex
	maxSize       int
	closed        bool
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	cleanupWg     sync.WaitGroup
	nowFunc       func() time.Time
}

// NewMemoryStore constructs the built-in in-process blacklist store, bounded
// to maxSize entries. When enableAutoCleanup is true, a background goroutine
// evicts expired entries every cleanupInterval. If nowFunc is nil, time.Now
// is used. The concrete type is returned so callers (and tests) can also
// reach Cleanup(); Manager consumes it through the narrower storeOps, the
// internal mirror of the public jwt.BlacklistStore.
func NewMemoryStore(maxSize int, cleanupInterval time.Duration, enableAutoCleanup bool, nowFunc func() time.Time) *memoryStore {
	// Ensure maxSize is positive to prevent nil map creation
	if maxSize <= 0 {
		maxSize = 10000 // Default to reasonable size
	}

	if nowFunc == nil {
		nowFunc = time.Now
	}

	store := &memoryStore{
		tokens:      make(map[string]time.Time, mapCapacity(maxSize)),
		maxSize:     maxSize,
		stopCleanup: make(chan struct{}),
		nowFunc:     nowFunc,
	}

	if enableAutoCleanup && cleanupInterval > 0 {
		store.startAutoCleanup(cleanupInterval)
	}

	return store
}

func (m *memoryStore) Add(tokenID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStoreClosed
	}

	if len(m.tokens) >= m.maxSize {
		m.cleanupExpiredUnsafe(m.nowFunc())
		if len(m.tokens) >= m.maxSize {
			// Evict at least one entry so a small maxSize still makes room.
			// Matches the RateLimiter's eviction strategy (max(count, 1));
			// without the floor, maxSize < 10 would evict zero and reject forever.
			// count >= 1 over a non-empty map, so eviction always frees space —
			// there is no "store full" rejection path after this point.
			m.evictOldestUnsafe(max(m.maxSize/10, 1))
		}
	}

	m.tokens[tokenID] = expiresAt
	return nil
}

func (m *memoryStore) Contains(tokenID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, ErrStoreClosed
	}

	expiresAt, exists := m.tokens[tokenID]
	if !exists {
		return false, nil
	}

	// Capture current time once to avoid TOCTOU issues
	now := m.nowFunc()
	if now.After(expiresAt) {
		return false, nil
	}

	return true, nil
}

func (m *memoryStore) Cleanup() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, ErrStoreClosed
	}

	return m.cleanupExpiredUnsafe(m.nowFunc()), nil
}

func (m *memoryStore) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true

	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.stopCleanup)
	}
	m.mu.Unlock()

	if m.cleanupTicker != nil {
		m.cleanupWg.Wait()
	}

	m.mu.Lock()
	clear(m.tokens)
	m.tokens = nil
	m.mu.Unlock()

	return nil
}

func (m *memoryStore) cleanupExpiredUnsafe(now time.Time) int {
	if len(m.tokens) == 0 {
		return 0
	}

	cleaned := 0
	for tokenID, expiresAt := range m.tokens {
		if now.After(expiresAt) {
			delete(m.tokens, tokenID)
			cleaned++
		}
	}
	return cleaned
}

func (m *memoryStore) evictOldestUnsafe(count int) {
	tokensLen := len(m.tokens)
	if tokensLen == 0 || count <= 0 {
		return
	}

	if count > tokensLen {
		count = tokensLen
	}

	type tokenEntry struct {
		id  string
		exp time.Time
	}

	entries := make([]tokenEntry, 0, tokensLen)
	for id, exp := range m.tokens {
		entries = append(entries, tokenEntry{id, exp})
	}

	// Use slices.SortFunc for O(n log n) instead of O(n²) selection sort
	slices.SortFunc(entries, func(a, b tokenEntry) int {
		switch {
		case a.exp.Before(b.exp):
			return -1
		case b.exp.Before(a.exp):
			return 1
		}
		return 0
	})

	for i := 0; i < count && i < len(entries); i++ {
		delete(m.tokens, entries[i].id)
	}
}

func (m *memoryStore) startAutoCleanup(interval time.Duration) {
	m.cleanupTicker = time.NewTicker(interval)

	// WaitGroup.Go (Go 1.25) handles Add(1)/Done() around f, so the body only
	// holds the select loop. Equivalent to the prior Add+go+defer Done form.
	m.cleanupWg.Go(func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				_, _ = m.Cleanup() // best-effort background cleanup
			case <-m.stopCleanup:
				return
			}
		}
	})
}
