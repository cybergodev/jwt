package jwt

import (
	"crypto/sha256"
	"encoding/hex"
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

func hashSecretKey(secretKey string) string {
	hash := sha256.Sum256([]byte(secretKey))
	return hex.EncodeToString(hash[:])
}

func CreateToken(secretKey string, claims Claims) (string, error) {
	processor, release, err := getProcessor(secretKey)
	if err != nil {
		return "", err
	}
	defer release()
	return processor.CreateToken(claims)
}

func ValidateToken(secretKey, tokenString string) (Claims, bool, error) {
	processor, release, err := getProcessor(secretKey)
	if err != nil {
		return Claims{}, false, err
	}
	defer release()
	return processor.ValidateToken(tokenString)
}

func RevokeToken(secretKey, tokenString string) error {
	processor, release, err := getProcessor(secretKey)
	if err != nil {
		return err
	}
	defer release()
	return processor.RevokeToken(tokenString)
}

func getProcessor(secretKey string) (*Processor, func(), error) {
	if len(secretKey) < 32 {
		return nil, func() {}, ErrInvalidSecretKey
	}

	keyHash := hashSecretKey(secretKey)
	now := time.Now().Unix()

	cache.mu.RLock()
	entry, exists := cache.entries[keyHash]
	if exists {
		entry.lastAccess.Store(now)
		entry.refCount.Add(1)
		cache.mu.RUnlock()
		return entry.processor, func() { entry.refCount.Add(-1) }, nil
	}
	cache.mu.RUnlock()

	processor, err := New(secretKey)
	if err != nil {
		return nil, func() {}, err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if entry, exists := cache.entries[keyHash]; exists {
		processor.Close()
		entry.lastAccess.Store(now)
		entry.refCount.Add(1)
		return entry.processor, func() { entry.refCount.Add(-1) }, nil
	}

	if len(cache.entries) >= maxCacheSize {
		evictOldestUnsafe()
	}

	entry = &cacheEntry{processor: processor}
	entry.lastAccess.Store(now)
	entry.refCount.Store(1)
	cache.entries[keyHash] = entry

	if now-cache.lastCleanup.Load() >= cacheCleanupInterval {
		go cleanupCacheAsync(now)
	}

	return processor, func() { entry.refCount.Add(-1) }, nil
}

func evictOldestUnsafe() {
	if len(cache.entries) == 0 {
		return
	}

	var oldestKey string
	oldestTime := int64(1<<63 - 1)

	for k, entry := range cache.entries {
		if entry.refCount.Load() > 0 {
			continue
		}
		if lastAccess := entry.lastAccess.Load(); lastAccess < oldestTime {
			oldestKey = k
			oldestTime = lastAccess
		}
	}

	if oldestKey != "" {
		if entry := cache.entries[oldestKey]; entry != nil && entry.processor != nil {
			entry.processor.Close()
		}
		delete(cache.entries, oldestKey)
	}
}

const (
	maxCacheSize         = 100
	cacheCleanupInterval = 300  // 5 minutes in seconds
	cacheMaxIdleTime     = 3600 // 1 hour in seconds
	batchEvictSize       = 5    // Evict multiple entries when cache is full
)

func cleanupCacheAsync(now int64) {
	if !cache.lastCleanup.CompareAndSwap(cache.lastCleanup.Load(), now) {
		return
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	toDelete := make([]string, 0, len(cache.entries)/10)
	for key, entry := range cache.entries {
		if entry.refCount.Load() > 0 {
			continue
		}
		if now-entry.lastAccess.Load() > cacheMaxIdleTime {
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		if entry := cache.entries[key]; entry != nil && entry.processor != nil {
			entry.processor.Close()
		}
		delete(cache.entries, key)
	}
}

type CacheStats struct {
	Size        int
	MaxSize     int
	LastCleanup int64
}

func GetCacheStats() CacheStats {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return CacheStats{
		Size:        len(cache.entries),
		MaxSize:     maxCacheSize,
		LastCleanup: cache.lastCleanup.Load(),
	}
}

func ClearCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	for _, entry := range cache.entries {
		if entry != nil && entry.processor != nil {
			entry.processor.Close()
		}
	}
	clear(cache.entries)
}
