package blacklist

import (
	"errors"
	"sync"
	"time"
)

var errStoreClosed = errors.New("blacklist store is closed")

// memoryStore implements the Store interface using in-memory storage.
// It is thread-safe and supports automatic cleanup of expired tokens.
type memoryStore struct {
	tokens  map[string]time.Time
	mu      sync.RWMutex
	maxSize int
	closed  bool

	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	cleanupWg     sync.WaitGroup
}

func NewMemoryStore(maxSize int, cleanupInterval time.Duration, enableAutoCleanup bool) Store {
	store := &memoryStore{
		tokens:      make(map[string]time.Time, maxSize/2),
		maxSize:     maxSize,
		stopCleanup: make(chan struct{}),
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
		return errStoreClosed
	}

	if len(m.tokens) >= m.maxSize {
		m.cleanupExpiredUnsafe(time.Now())
		if len(m.tokens) >= m.maxSize {
			m.evictOldestUnsafe(m.maxSize / 10)
		}
	}

	m.tokens[tokenID] = expiresAt
	return nil
}

func (m *memoryStore) Contains(tokenID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false, errStoreClosed
	}

	expiresAt, exists := m.tokens[tokenID]
	if !exists || time.Now().After(expiresAt) {
		return false, nil
	}

	return true, nil
}

func (m *memoryStore) Cleanup() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, errStoreClosed
	}

	return m.cleanupExpiredUnsafe(time.Now()), nil
}

func (m *memoryStore) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.stopCleanup)
		m.cleanupWg.Wait()
		m.cleanupTicker = nil
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

	evicted := 0
	oldestTime := time.Now().Add(100 * 365 * 24 * time.Hour)
	var oldestID string

	for evicted < count {
		oldestTime = time.Now().Add(100 * 365 * 24 * time.Hour)
		oldestID = ""

		for id, exp := range m.tokens {
			if exp.Before(oldestTime) {
				oldestTime = exp
				oldestID = id
			}
		}

		if oldestID != "" {
			delete(m.tokens, oldestID)
			evicted++
		} else {
			break
		}
	}
}

func (m *memoryStore) startAutoCleanup(interval time.Duration) {
	m.cleanupTicker = time.NewTicker(interval)
	m.cleanupWg.Add(1)

	go func() {
		defer m.cleanupWg.Done()
		for {
			select {
			case <-m.cleanupTicker.C:
				m.Cleanup()
			case <-m.stopCleanup:
				return
			}
		}
	}()
}
