package jwt

import (
	"sync"
	"sync/atomic"
	"time"
)

type cacheEntry struct {
	processor  *Processor
	lastAccess atomic.Int64
	refCount   atomic.Int32
}

type processorCache struct {
	entries     map[string]*cacheEntry
	mu          sync.RWMutex
	lastCleanup atomic.Int64
}

var cache = &processorCache{
	entries: make(map[string]*cacheEntry, 16),
}

// CreateToken creates a JWT token using a cached processor.
// This is a convenience function for simple use cases without rate limiting.
// For production environments with rate limiting, use the Processor API.
// The secret key must be at least 32 bytes long.
func CreateToken(secretKey string, claims Claims) (string, error) {
	if len(secretKey) < 32 {
		return "", ErrInvalidSecretKey
	}

	processor, release, err := getProcessor(secretKey)
	if err != nil {
		return "", err
	}
	defer release()

	return processor.CreateToken(claims)
}

// ValidateToken validates a JWT token using a cached processor.
// This is a convenience function for simple use cases without rate limiting.
// For production environments with rate limiting, use the Processor API.
// The secret key must be at least 32 bytes long.
func ValidateToken(secretKey, tokenString string) (Claims, bool, error) {
	if len(secretKey) < 32 {
		return Claims{}, false, ErrInvalidSecretKey
	}

	processor, release, err := getProcessor(secretKey)
	if err != nil {
		return Claims{}, false, err
	}
	defer release()

	return processor.ValidateToken(tokenString)
}

// RevokeToken revokes a JWT token using a cached processor.
// This is a convenience function for simple use cases without rate limiting.
// For production environments with rate limiting, use the Processor API.
// The secret key must be at least 32 bytes long.
func RevokeToken(secretKey, tokenString string) error {
	if len(secretKey) < 32 {
		return ErrInvalidSecretKey
	}

	processor, release, err := getProcessor(secretKey)
	if err != nil {
		return err
	}
	defer release()

	return processor.RevokeToken(tokenString)
}

func getProcessor(secretKey string) (*Processor, func(), error) {
	now := time.Now().Unix()

	cache.mu.RLock()
	entry, exists := cache.entries[secretKey]
	cache.mu.RUnlock()

	if exists {
		entry.lastAccess.Store(now)
		entry.refCount.Add(1)
		return entry.processor, func() { entry.refCount.Add(-1) }, nil
	}

	processor, err := New(secretKey)
	if err != nil {
		return nil, func() {}, err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if entry, exists := cache.entries[secretKey]; exists {
		processor.Close()
		entry.lastAccess.Store(now)
		entry.refCount.Add(1)
		return entry.processor, func() { entry.refCount.Add(-1) }, nil
	}

	const maxCacheSize = 100
	if len(cache.entries) >= maxCacheSize {
		evictOldestUnsafe()
	}

	entry = &cacheEntry{processor: processor}
	entry.lastAccess.Store(now)
	entry.refCount.Store(1)
	cache.entries[secretKey] = entry

	cleanupCacheIfNeeded(now)

	return processor, func() { entry.refCount.Add(-1) }, nil
}

func evictOldestUnsafe() {
	if len(cache.entries) == 0 {
		return
	}

	oldestKey := ""
	oldestTime := int64(1<<63 - 1)

	for k, entry := range cache.entries {
		if entry.refCount.Load() > 0 {
			continue
		}
		lastAccess := entry.lastAccess.Load()
		if lastAccess < oldestTime {
			oldestKey = k
			oldestTime = lastAccess
		}
	}

	if oldestKey != "" {
		if entry, exists := cache.entries[oldestKey]; exists {
			if entry.processor != nil {
				entry.processor.Close()
			}
			delete(cache.entries, oldestKey)
		}
	}
}

const (
	cacheCleanupInterval = 300  // 5 minutes in seconds
	cacheMaxIdleTime     = 3600 // 1 hour in seconds
)

func cleanupCacheIfNeeded(now int64) {
	lastCleanup := cache.lastCleanup.Load()
	if now-lastCleanup < cacheCleanupInterval {
		return
	}

	if !cache.lastCleanup.CompareAndSwap(lastCleanup, now) {
		return
	}

	for key, entry := range cache.entries {
		if entry.refCount.Load() > 0 {
			continue
		}
		if now-entry.lastAccess.Load() > cacheMaxIdleTime {
			if entry.processor != nil {
				entry.processor.Close()
			}
			delete(cache.entries, key)
		}
	}
}

// ClearCache clears all cached processors and releases their resources.
// This is primarily useful for testing and graceful shutdown scenarios.
// After calling ClearCache, subsequent calls to convenience functions will create new processors.
func ClearCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	for key, entry := range cache.entries {
		if entry.processor != nil {
			entry.processor.Close()
		}
		delete(cache.entries, key)
	}
}
