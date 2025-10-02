package jwt

import (
	"crypto/sha256"
	"sync"
	"time"
)

type cacheEntry struct {
	processor  *Processor
	lastAccess time.Time
	refCount   int32
}

var (
	processorCache = make(map[string]*cacheEntry)
	cacheMutex     sync.RWMutex
	maxCacheSize   = 100
)

// CreateToken creates a JWT token using a cached processor
func CreateToken(secretKey string, claims Claims) (string, error) {
	processor, err := getOrCreateProcessor(secretKey)
	if err != nil {
		return "", err
	}
	return processor.CreateToken(claims)
}

// ValidateToken validates a JWT token using a cached processor
func ValidateToken(secretKey, tokenString string) (*Claims, bool, error) {
	processor, err := getOrCreateProcessor(secretKey)
	if err != nil {
		return nil, false, err
	}
	return processor.ValidateToken(tokenString)
}

// RevokeToken revokes a JWT token using a cached processor
func RevokeToken(secretKey, tokenString string) error {
	processor, err := getOrCreateProcessor(secretKey)
	if err != nil {
		return err
	}
	return processor.RevokeToken(tokenString)
}

func getOrCreateProcessor(secretKey string) (*Processor, error) {
	if len(secretKey) < 32 {
		return nil, ErrInvalidSecretKey
	}

	hash := sha256.Sum256([]byte(secretKey))
	cacheKey := string(hash[:16])

	cacheMutex.RLock()
	if entry, exists := processorCache[cacheKey]; exists {
		entry.lastAccess = time.Now()
		processor := entry.processor
		cacheMutex.RUnlock()
		return processor, nil
	}
	cacheMutex.RUnlock()

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if entry, exists := processorCache[cacheKey]; exists {
		entry.lastAccess = time.Now()
		return entry.processor, nil
	}

	config := DefaultConfig()
	config.EnableRateLimit = false

	processor, err := New(secretKey, config)
	if err != nil {
		return nil, err
	}

	if len(processorCache) >= maxCacheSize {
		evictLRUProcessor()
	}

	processorCache[cacheKey] = &cacheEntry{
		processor:  processor,
		lastAccess: time.Now(),
		refCount:   0,
	}
	return processor, nil
}

func evictLRUProcessor() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for k, entry := range processorCache {
		if entry.refCount > 0 {
			continue
		}
		if first || entry.lastAccess.Before(oldestTime) {
			oldestKey = k
			oldestTime = entry.lastAccess
			first = false
		}
	}

	if oldestKey != "" {
		if entry, exists := processorCache[oldestKey]; exists {
			entry.processor.Close()
			delete(processorCache, oldestKey)
		}
	}
}

// ClearProcessorCache clears the processor cache
func ClearProcessorCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	for _, entry := range processorCache {
		entry.processor.Close()
	}
	clear(processorCache)
}
