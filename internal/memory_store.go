package internal

import (
	"errors"
	"sync"
	"time"
)

var errStoreClosed = errors.New("blacklist store is closed")

type memoryStore struct {
	tokens        map[string]time.Time
	mu            sync.RWMutex
	maxSize       int
	closed        bool
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

	for i := 0; i < count && i < len(entries); i++ {
		minIdx := i
		for j := i + 1; j < len(entries); j++ {
			if entries[j].exp.Before(entries[minIdx].exp) {
				minIdx = j
			}
		}
		if minIdx != i {
			entries[i], entries[minIdx] = entries[minIdx], entries[i]
		}
		delete(m.tokens, entries[i].id)
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
