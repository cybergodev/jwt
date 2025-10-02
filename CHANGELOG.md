# cybergodev/jwt - Release Notes


===============================================================

[//]: # (---)

[//]: # ()
[//]: # (## v1.0.1 - Previous Release)

[//]: # ()
[//]: # (### Added)

[//]: # ()
[//]: # ()
[//]: # (### Changed)

[//]: # ()
[//]: # ()
[//]: # (### Fixed)


---

## v1.0.0 - Initial Release (2025-10-02)

### Added

#### Core Features
- ⚡ **Minimal API** - 3 core functions: `CreateToken`, `ValidateToken`, `RevokeToken`
- 🛡️ **Production-Ready Security** - Comprehensive security testing and protection
- 🚀 **High Performance** - Object pool + cache optimization
- 📦 **Zero Dependencies** - Only Go standard library

#### Security Features
- Advanced weak key detection with entropy analysis
- Constant-time cryptographic operations
- 5-pass secure memory wiping (DoD 5220.22-M standard)
- Protection against timing attacks, injection attacks, and DoS attacks
- Algorithm confusion attack prevention
- Comprehensive input validation

#### Token Management
- Token creation with customizable claims
- Token validation with blacklist support
- Token revocation and blacklist management
- Refresh token support
- Automatic token expiration handling

#### Rate Limiting
- Configurable rate limiting for processor mode
- No rate limiting for convenience functions
- Token creation, validation, and login attempt limits
- Automatic cleanup of rate limit buckets

#### Configuration
- Flexible configuration system
- Support for HS256, HS384, HS512 signing methods
- Customizable token TTL (access and refresh tokens)
- Blacklist configuration with auto-cleanup
- Timezone support


### Performance
- Token creation: ~85,000 ops/sec
- Token validation: ~90,000 ops/sec
- Memory usage: ~3.7KB per operation
- Concurrent performance: Linear scaling up to CPU cores




