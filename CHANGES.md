# Changelog

All notable changes to the cybergodev/jwt library will be documented in this file.

[//]: # (The format is based on [Keep a Changelog]&#40;https://keepachangelog.com/en/1.0.0/&#41;,)
[//]: # (and this project adheres to [Semantic Versioning]&#40;https://semver.org/spec/v2.0.0.html&#41;.)


---

## v1.0.1 - Performance & Security Enhancements (2025-12-01)

### Added
- Comprehensive godoc comments for all exported types and functions
- Thread-safety documentation for all public APIs
- Input validation for empty tokens and invalid parameters
- Reference counting in convenience cache to prevent premature processor closure
- `ClearCache()` function for proper cleanup in tests and shutdown scenarios
- `IsClosed()` method for processor state checking

### Changed
- **BREAKING**: Simplified rate limiting configuration - removed `RateLimitConfig` type
  - Old: `config.RateLimit = &jwt.RateLimitConfig{MaxRate: 100, Window: time.Minute}`
  - New: `config.RateLimitRate = 100; config.RateLimitWindow = time.Minute`
- Optimized `ValidateToken` return type from `*Claims` to `Claims` to prevent memory leaks
- Replaced `SecureBytes` wrapper with direct `[]byte` for HMAC keys (reduced overhead)
- Upgraded processor closed state from `sync.Mutex` to `atomic.Bool` for lock-free operations
- Changed convenience cache from `sync.Mutex` to `sync.RWMutex` for better read concurrency
- Optimized dangerous pattern detection algorithm (3x faster, O(n+m*p) complexity)
- Improved blacklist eviction strategy to evict tokens with earliest expiration time
- Simplified Claims pool with lazy allocation (40% reduction in memory footprint)
- Removed redundant security functions (`SecureCompare`, `SecureRandomDelay`) - use stdlib directly

### Fixed
- Memory leak in `ValidateToken` where pooled Claims objects were escaping
- Memory leak in convenience cache where processors weren't properly closed on eviction
- Race condition in convenience cache with atomic operations
- Race condition in processor cache reference counting
- Rate limiter goroutine leak when window is 0
- Timing attack vulnerability in `SecureRandomDelay()` (now uses proper `time.Sleep`)
- Config validation bypass in `NewWithBlacklist`
- Redundant token validity checks in validation flow

### Performance
- 10-15% improvement in validation hot path
- 50% faster pattern matching with zero allocations
- 40% reduction in Claims pool allocation overhead
- Reduced lock contention in processor operations
- Eliminated unnecessary error wrapping in hot paths
- Optimized string validation with zero allocations
- O(1) algorithm security checks with map-based lookup

### Security
- Fixed critical timing attack vulnerability in random delay function
- Improved constant-time operations using `crypto/hmac.Equal()`
- Enhanced input validation across all public APIs
- Better error handling for cryptographic operations
- Maintained all security protections while improving performance

### Code Quality
- Removed ~350 lines of redundant/unused code
- Eliminated over-engineered abstractions (`SecureBytes`, redundant wrappers)
- Improved error messages with proper context wrapping
- Unified type definitions to reduce duplication
- Enhanced code consistency and maintainability
- Test coverage improved to 90.4% (main), 94.9% (blacklist), 91.8% (core), 98.4% (security)

---

## v1.0.0 - Initial Release (2025-10-02)

### Added

- Minimal API with 3 core functions: `CreateToken`, `ValidateToken`, `RevokeToken`
- Production-ready security with comprehensive testing and protection
- High performance with object pool and cache optimization
- Zero external dependencies - standard library only
- Advanced weak key detection with entropy analysis
- Constant-time cryptographic operations
- 5-pass secure memory wiping (DoD 5220.22-M standard)
- Protection against timing attacks, injection attacks, and DoS attacks
- Algorithm confusion attack prevention
- Comprehensive input validation at all API boundaries
- Token creation with customizable claims
- Token validation with blacklist support
- Token revocation and blacklist management
- Refresh token support with automatic expiration handling
- Configurable rate limiting for processor mode
- Token creation, validation, and login attempt rate limits
- Automatic cleanup of rate limit buckets
- Flexible configuration system with sensible defaults
- Support for HS256, HS384, HS512 signing methods
- Customizable token TTL for access and refresh tokens
- Blacklist configuration with auto-cleanup
- Timezone support for token timestamps
- Performance benchmarks: ~85,000 ops/sec (creation), ~90,000 ops/sec (validation)
- Memory efficiency: ~3.7KB per operation
- Concurrent performance with linear scaling up to CPU cores

### Changed
- N/A (Initial release)

### Fixed
- N/A (Initial release)

---


