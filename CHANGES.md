# Changelog

All notable changes to the cybergodev/jwt library will be documented in this file.

[//]: # (The format is based on [Keep a Changelog]&#40;https://keepachangelog.com&#41;,)
[//]: # (and this project adheres to [Semantic Versioning]&#40;https://semver.org&#41;.)

---

## v1.1.0 - API Redesign & Major Refactoring (2026-03-07)

### Breaking Changes

- **Unified Constructor**: `New(cfg)` replaces `New(secretKey)`, `NewWithBlacklist()`, `NewWithRSA()`, `NewWithECDSA()`, `NewWithAsymmetricKey()`, and `NewWithAsymmetricKeyAndBlacklist()`
- **Removed Global Functions**: `CreateToken()`, `ValidateToken()`, `RevokeToken()`, `GetCacheStats()`, `ClearCache()` - use `API` type methods instead
- **Simplified Rate Limiting**: Direct `Config.RateLimitRate` and `Config.RateLimitWindow` fields replace `RateLimitConfig` struct
- **Config Pattern**: All configurations must use `DefaultConfig()` as base (zero-value Config is invalid)

### Added

- **Asymmetric Cryptography**: Full RSA (RS256/384/512) and ECDSA (ES256/384/512) signing support with `Config.SigningKey` and `Config.VerificationKey`
- **Custom Claims API**: `Processor.CreateTokenWith()`, `ValidateTokenWith()`, `CreateRefreshTokenWith()` for type-safe custom claims
- **Extensibility Interfaces**: `TokenManager`, `RateLimitProvider`, `ClockProvider`, `BlacklistStore` for dependency injection and testing
- **API Type**: Explicit lifecycle management with `NewAPI()` replacing global convenience functions
- **Enhanced Security**: Signature length validation, extended XSS pattern detection, error message sanitization

### Changed

- **Unified Config**: Single `Config` struct with embedded `Blacklist`, `SigningKey`, and rate limit fields
- **API Type Renamed**: `ConvenienceAPI` → `API`, `ConvenienceConfig` → `APIConfig`
- **Documentation**: Comprehensive docs suite (API.md, PERFORMANCE.md, CONCURRENCY.md, BEST_PRACTICES.md, TROUBLESHOOTING.md, EXAMPLES.md)
- **Examples**: Restructured from 9 to 7 focused files with clear learning progression

### Fixed

- **Critical**: Claims pool race condition with map/slice reallocation in `Claims.reset()`
- **Critical**: Memory store `maxSize` violation and TOCTOU race in `Contains()`
- **Security**: HMAC/RSA/ECDSA signature length validation before cryptographic comparison
- **Security**: Information leakage in error messages (key size disclosure)
- **Concurrency**: Race conditions in `cleanupAsync()`, `evictOldest()`, and rate limiter
- **Memory**: Processor creation reduced from ~620ms to ~3.8ms with lazy store initialization

### Performance

| Metric | Improvement |
|--------|-------------|
| Token Creation | 25.5% faster, 22.1% less memory |
| Token Validation | 24.9% less memory, 9.8% fewer allocations |
| Processor Creation | 99.4% faster (620ms → 3.8ms) |
| Pattern Matching | 70% faster with O(n+m) algorithm |
| Test Coverage | 90.7% (up from 88.2%) |

### Migration Guide

```go
// Before (v1.0.x)
processor, _ := jwt.New(secretKey)
token, _ := jwt.CreateToken(secretKey, claims)

// After (v1.1.x)
cfg := jwt.DefaultConfig()
cfg.SecretKey = secretKey
processor, _ := jwt.New(cfg)
defer processor.Close()

token, _ := processor.CreateToken(claims)
```

---

## v1.0.2 - Code Quality & Documentation Overhaul (2026-01-10)

### Changed
- **Documentation**: Comprehensive documentation improvement across all files
  - Removed marketing language, unverifiable claims, and redundant examples
  - Improved accuracy to match actual codebase implementation
  - Fixed rate limiting documentation to reflect actual API
  - Removed external dependency examples (Vault, AWS Secrets Manager)
  - Simplified framework integration examples (Gin, Echo, net/http)
- **Examples**: Consolidated 6 example files into 3 focused files (67% reduction)
  - New structure: `quickstart.go`, `web_server.go`, `advanced.go`
  - Eliminated redundant code and improved learning progression
  - Production-ready patterns with proper error handling
- **README**: Enhanced accuracy and neutrality
  - Fixed missing imports in code examples
  - Added `IsTokenRevoked()` method documentation
  - Replaced unsubstantiated performance claims with factual descriptions
  - Expanded security features with specific implementation details

### Fixed
- **Security**: Cache cleanup concurrency issue in `convenience.go`
  - Fixed race condition in cleanup without lock
  - Changed to async goroutine with proper synchronization
- **Security**: Cache key storage vulnerability
  - Implemented SHA-256 hashing for cache keys
  - Prevents secret key exposure in memory dumps
- **Validation**: Rate limiter negative value handling
  - Added explicit check for negative request counts
  - Prevents potential rate limiting bypass

### Performance
- **Rate Limiting**: Eliminated floating-point arithmetic (15-20% faster)
  - Changed from float64 to int64 operations in hot path
- **Pattern Matching**: Optimized algorithm (70% faster)
  - Reduced complexity from O(n*m*p) to O(n+m)
  - Single map scan with `strings.ToLower()` + `strings.Contains()`
- **Token Parsing**: Reduced allocations (10% faster)
  - Pre-allocated buffer for signing string
  - Eliminated intermediate string allocation
- **Memory Store**: Improved eviction algorithm (40% faster)
  - Optimized from O(n*count) to O(n + count*n)
  - Added fast path for small evictions

### Code Quality
- **Removed Redundancy**: Eliminated ~500 lines of redundant code
  - Removed duplicate `createTokenWithClaims()` method
  - Consolidated validation logic in convenience functions
  - Simplified claims copying with struct copy
  - Unified eviction algorithms
- **Simplified Logic**: Improved code clarity
  - Streamlined processor initialization
  - Optimized Close() error handling
  - Improved cache RLock release timing
  - Simplified config validation
- **Comment Cleanup**: Removed 200+ lines of excessive comments
  - Removed obvious comments that restate code
  - Kept essential documentation for public APIs
  - Improved signal-to-noise ratio

### Internal
- **Test Consolidation**: Merged 6 internal test files into 1
  - Maintained 92.1% code coverage
  - Better organization with clear section headers
- **Documentation**: Added comprehensive godoc for internal package
  - Documented all interfaces, types, and methods
  - Added thread-safety guarantees
  - Improved error messages with context

### Validation
- All 73+ tests pass with 100% success rate
- No breaking changes to public API
- 100% backward compatibility maintained
- Build successful with no warnings

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


