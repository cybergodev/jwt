package jwt

import (
	"crypto/sha256"
	"sync"
)

// processorCache caches processors for reuse
var (
	processorCache = make(map[string]*Processor)
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

// getOrCreateProcessor gets or creates a cached processor with optimized caching
// This processor is created without rate limiting for convenience methods
func getOrCreateProcessor(secretKey string) (*Processor, error) {
	if len(secretKey) < 32 {
		return nil, ErrInvalidSecretKey
	}

	// Create secure cache key using first 16 bytes of hash
	hash := sha256.Sum256([]byte(secretKey))
	cacheKey := string(hash[:16]) // More efficient than hex formatting

	// Fast path: read lock only
	cacheMutex.RLock()
	if processor, exists := processorCache[cacheKey]; exists {
		cacheMutex.RUnlock()
		return processor, nil
	}
	cacheMutex.RUnlock()

	// Slow path: write lock for creation
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// Double-check pattern
	if processor, exists := processorCache[cacheKey]; exists {
		return processor, nil
	}

	// Create new processor without rate limiting for convenience methods
	// Use default config with rate limiting explicitly disabled
	config := DefaultConfig()
	config.EnableRateLimit = false // Ensure rate limiting is disabled

	processor, err := New(secretKey, config)
	if err != nil {
		return nil, err
	}

	// Simple cache eviction: remove oldest when at capacity
	if len(processorCache) >= maxCacheSize {
		evictOldestProcessor()
	}

	processorCache[cacheKey] = processor
	return processor, nil
}

// evictOldestProcessor removes the first processor from cache (FIFO)
func evictOldestProcessor() {
	for k, processor := range processorCache {
		processor.Close()
		delete(processorCache, k)
		break // Only remove one
	}
}

// ClearProcessorCache clears the processor cache
func ClearProcessorCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	for _, processor := range processorCache {
		processor.Close()
	}
	clear(processorCache)
}
