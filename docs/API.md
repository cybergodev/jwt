# JWT Library - API Reference

This document provides the complete API reference for the JWT library, including function signatures, parameters, return values, and practical examples.

## 🚀 Quick Start

```go
import "github.com/cybergodev/jwt"

// Create token
token, err := jwt.CreateToken(secretKey, jwt.Claims{UserID: "123", Role: "admin"})

// Validate token
claims, valid, err := jwt.ValidateToken(secretKey, token)
```

## 📋 API Reference Index

### 🎯 [Quick Functions](#-quick-functions) - Simple one-line operations
- [`CreateToken`](#createtoken) - Create JWT tokens instantly
- [`ValidateToken`](#validatetoken) - Validate tokens with full security
- [`RevokeToken`](#revoketoken) - Revoke tokens immediately

### 🏭 [Processor API](#-processor-api) - Advanced control and configuration
- [`New`](#new) - Create processor with default settings
- [`NewWithBlacklist`](#newwithblacklist) - Create with custom blacklist
- [`CreateToken`](#processorcreatetoken) - Advanced token creation
- [`ValidateToken`](#processorvalidatetoken) - Advanced validation
- [`RefreshToken`](#processorrefreshtoken) - Token refresh mechanism
- [`RevokeToken`](#processorrevoketoken) - Token revocation
- [`Close`](#processorclose) - Secure cleanup

### ⚙️ [Configuration](#-configuration) - Setup and customization
- [`Config`](#config) - Main configuration structure
- [`BlacklistConfig`](#blacklistconfig) - Blacklist settings
- [`RateLimitConfig`](#ratelimitconfig) - Rate limiting setup

### 📊 [Data Types](#-data-types) - Core data structures
- [`Claims`](#claims) - JWT claims structure
- [`SigningMethod`](#signingmethod) - Supported algorithms
- [`NumericDate`](#numericdate) - JWT timestamp handling

### ❌ [Error Handling](#-error-handling) - Comprehensive error types
- [Error Constants](#error-constants) - All error types
- [Error Handling Patterns](#error-handling-patterns) - Best practices

---

## 🎯 Quick Functions

Simple convenience functions with automatic processor caching. No rate limiting is applied, making them suitable for internal services and trusted environments.

### CreateToken

Creates a JWT token using an internal cached processor.

```go
func CreateToken(secretKey string, claims Claims) (string, error)
```

#### Parameters
| Parameter   | Type     | Description              | Requirements            |
|-------------|----------|--------------------------|-------------------------|
| `secretKey` | `string` | Cryptographic secret key | ≥32 bytes, high entropy |
| `claims`    | `Claims` | JWT payload data         | Valid claims structure  |

#### Returns
| Type     | Description                       |
|----------|-----------------------------------|
| `string` | Base64-encoded JWT token          |
| `error`  | Error details or `nil` on success |

#### Example
```go
claims := jwt.Claims{
    UserID:   "user_12345",
    Username: "john.doe",
    Role:     "admin",
}
claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Minute))

secretKey := "your-secret-key-at-least-32-bytes-long!"
token, err := jwt.CreateToken(secretKey, claims)
if err != nil {
    return fmt.Errorf("token creation failed: %w", err)
}
```

### ValidateToken

Validates a JWT token including signature verification, expiration, and blacklist checks.

```go
func ValidateToken(secretKey, tokenString string) (*Claims, bool, error)
```

#### Parameters
| Parameter     | Type     | Description                             |
|---------------|----------|-----------------------------------------|
| `secretKey`   | `string` | Same secret key used for token creation |
| `tokenString` | `string` | JWT token to validate                   |

#### Returns
| Type      | Description                                  |
|-----------|----------------------------------------------|
| `*Claims` | Parsed and validated claims (nil if invalid) |
| `bool`    | `true` if token is valid and not expired     |
| `error`   | Validation error details or `nil`            |

#### Example
```go
claims, valid, err := jwt.ValidateToken(secretKey, tokenString)
if err != nil || !valid {
    return fmt.Errorf("invalid token")
}

fmt.Printf("User: %s, Role: %s\n", claims.Username, claims.Role)
```

### RevokeToken

Revokes a JWT token by adding it to the blacklist.

```go
func RevokeToken(secretKey, tokenString string) error
```

#### Parameters
| Parameter     | Type     | Description                  |
|---------------|----------|------------------------------|
| `secretKey`   | `string` | Secret key for token parsing |
| `tokenString` | `string` | JWT token to revoke          |

#### Returns
| Type    | Description                          |
|---------|--------------------------------------|
| `error` | Revocation error or `nil` on success |

#### Example
```go
err := jwt.RevokeToken(secretKey, token)
if err != nil {
    return fmt.Errorf("revocation failed: %w", err)
}
```

---

## 🏭 Processor API

The Processor API provides fine-grained control over JWT operations with custom configurations, blacklist management, and optional rate limiting.

### New

Creates a new JWT processor with default configuration.

```go
func New(secretKey string, configs ...Config) (*Processor, error)
```

#### Parameters
| Parameter   | Type        | Description                      | Requirements            |
|-------------|-------------|----------------------------------|-------------------------|
| `secretKey` | `string`    | Cryptographic secret key         | ≥32 bytes, high entropy |
| `configs`   | `...Config` | Optional configuration overrides | Valid Config struct     |

#### Returns
| Type         | Description                       |
|--------------|-----------------------------------|
| `*Processor` | Configured JWT processor instance |
| `error`      | Configuration or validation error |

#### Example: Basic Processor
```go
// Create processor with default settings
processor, err := jwt.New(secretKey)
if err != nil {
    return fmt.Errorf("failed to create JWT processor: %w", err)
}
defer processor.Close() // Always close to free resources

// Use processor for operations
token, err := processor.CreateToken(claims)
```

#### Example: Custom Configuration
```go
// Custom configuration for production
config := jwt.Config{
    AccessTokenTTL:  10 * time.Minute,     // Short-lived tokens
    RefreshTokenTTL: 24 * time.Hour,       // Daily refresh
    Issuer:          "myapp-production",    // App identifier
    SigningMethod:   jwt.SigningMethodHS512, // Stronger algorithm
}

processor, err := jwt.New(secretKey, config)
if err != nil {
    log.Fatalf("Processor creation failed: %v", err)
}
defer processor.Close()

token, err := processor.CreateToken(claims)
```

### NewWithBlacklist

Creates a JWT processor with custom blacklist configuration. Essential for applications requiring token revocation capabilities.

```go
func NewWithBlacklist(secretKey string, blacklistConfig BlacklistConfig, configs ...Config) (*Processor, error)
```

#### Parameters
| Parameter         | Type              | Description                 |
|-------------------|-------------------|-----------------------------|
| `secretKey`       | `string`          | Cryptographic secret key    |
| `blacklistConfig` | `BlacklistConfig` | Blacklist behavior settings |
| `configs`         | `...Config`       | Optional JWT configuration  |

#### Returns
| Type         | Description                      |
|--------------|----------------------------------|
| `*Processor` | Processor with blacklist support |
| `error`      | Configuration error              |

#### Example: Production Blacklist Setup
```go
// High-performance blacklist for production
blacklistConfig := jwt.BlacklistConfig{
    MaxSize:           100000,              // 100K revoked tokens
    CleanupInterval:   5 * time.Minute,     // Regular cleanup
    EnableAutoCleanup: true,                // Automatic maintenance
    StoreType:        "memory",             // Fast in-memory storage
}

config := jwt.Config{
    AccessTokenTTL:  15 * time.Minute,
    RefreshTokenTTL: 7 * 24 * time.Hour,
    Issuer:          "secure-app-v2",
}

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
if err != nil {
    log.Fatalf("Secure processor creation failed: %v", err)
}
defer processor.Close()
```

### Rate Limiting Configuration

Rate limiting can be enabled through the Config structure. It is disabled by default.

#### Config Structure
```go
type Config struct {
    SecretKey        string
    AccessTokenTTL   time.Duration
    RefreshTokenTTL  time.Duration
    Issuer           string
    SigningMethod    SigningMethod
    EnableRateLimit  bool          // Enable rate limiting (default: false)
    RateLimitRate    int           // Requests per window (default: 100)
    RateLimitWindow  time.Duration // Time window (default: 1 minute)
}
```

#### Example: Enable Rate Limiting
```go
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100           // 100 requests per window
config.RateLimitWindow = time.Minute // Per minute

processor, err := jwt.New(secretKey, config)
if err != nil {
    return err
}
defer processor.Close()

token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    return errors.New("rate limit exceeded")
}
```

#### Example: Custom Rate Limiter
```go
// Create custom rate limiter
rateLimiter := jwt.NewRateLimiter(200, time.Minute)

config := jwt.DefaultConfig()
config.RateLimiter = rateLimiter

processor, err := jwt.New(secretKey, config)
```

### Processor.CreateToken

Creates a JWT token with the processor's configuration.

```go
func (p *Processor) CreateToken(claims Claims) (string, error)
```

#### Example
```go
claims := jwt.Claims{
    UserID: "user123",
    Role:   "admin",
}
claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Minute))

token, err := processor.CreateToken(claims)
if err != nil {
    return fmt.Errorf("token creation failed: %w", err)
}
```

### Processor.ValidateToken

Validates a JWT token using the processor's configuration.

```go
func (p *Processor) ValidateToken(tokenString string) (Claims, bool, error)
```

#### Example
```go
claims, valid, err := processor.ValidateToken(token)
if err != nil || !valid {
    return fmt.Errorf("invalid token")
}

fmt.Printf("User: %s\n", claims.UserID)
```

### Processor.CreateRefreshToken

Creates a long-lived refresh token using the configured RefreshTokenTTL.

```go
func (p *Processor) CreateRefreshToken(claims Claims) (string, error)
```

#### Example
```go
refreshToken, err := processor.CreateRefreshToken(claims)
if err != nil {
    return fmt.Errorf("refresh token creation failed: %w", err)
}
```

### Processor.RefreshToken

Creates a new access token from a valid refresh token.

```go
func (p *Processor) RefreshToken(refreshTokenString string) (string, error)
```

#### Example
```go
newAccessToken, err := processor.RefreshToken(refreshToken)
if err != nil {
    return fmt.Errorf("token refresh failed: %w", err)
}
```

### Processor.RevokeToken

Revokes a JWT token by adding it to the blacklist.

```go
func (p *Processor) RevokeToken(tokenString string) error
```

#### Example
```go
err := processor.RevokeToken(token)
if err != nil {
    return fmt.Errorf("revocation failed: %w", err)
}
```

### Processor.Close

Closes the processor and cleans up resources.

```go
func (p *Processor) Close() error
```

#### Example
```go
processor, err := jwt.New(secretKey)
if err != nil {
    return err
}
defer processor.Close()
```

---

## ⚙️ Configuration

### Config

Main configuration structure for JWT processors.

```go
type Config struct {
    SecretKey        string
    AccessTokenTTL   time.Duration
    RefreshTokenTTL  time.Duration
    Issuer           string
    SigningMethod    SigningMethod
    EnableRateLimit  bool
    RateLimitRate    int
    RateLimitWindow  time.Duration
    RateLimiter      *RateLimiter
}
```

#### Configuration Fields

| Field             | Type            | Description              | Default         |
|-------------------|-----------------|--------------------------|-----------------|
| `SecretKey`       | `string`        | Cryptographic secret key | `""`            |
| `AccessTokenTTL`  | `time.Duration` | Access token lifetime    | `15m`           |
| `RefreshTokenTTL` | `time.Duration` | Refresh token lifetime   | `168h` (7 days) |
| `Issuer`          | `string`        | Token issuer identifier  | `"jwt-service"` |
| `SigningMethod`   | `SigningMethod` | HMAC algorithm           | `HS256`         |
| `EnableRateLimit` | `bool`          | Enable rate limiting     | `false`         |
| `RateLimitRate`   | `int`           | Requests per window      | `100`           |
| `RateLimitWindow` | `time.Duration` | Rate limit window        | `1m`            |
| `RateLimiter`     | `*RateLimiter`  | Custom rate limiter      | `nil`           |

### DefaultConfig

Returns default configuration.

```go
func DefaultConfig() Config
```

#### Example
```go
config := jwt.DefaultConfig()
config.SecretKey = os.Getenv("JWT_SECRET_KEY")
config.AccessTokenTTL = 10 * time.Minute
config.RefreshTokenTTL = 24 * time.Hour

processor, err := jwt.New(secretKey, config)
```

### BlacklistConfig

Configuration for token revocation.

```go
type BlacklistConfig struct {
    MaxSize           int
    CleanupInterval   time.Duration
    EnableAutoCleanup bool
}
```

#### Example
```go
blacklistConfig := jwt.DefaultBlacklistConfig()
blacklistConfig.MaxSize = 100000
blacklistConfig.CleanupInterval = 2 * time.Minute

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

---

## 📊 Data Types

### Claims

JWT claims structure with custom fields and standard registered claims.

```go
type Claims struct {
    UserID      string         `json:"user_id,omitempty"`
    Username    string         `json:"username,omitempty"`
    Role        string         `json:"role,omitempty"`
    Permissions []string       `json:"permissions,omitempty"`
    Scopes      []string       `json:"scopes,omitempty"`
    Extra       map[string]any `json:"extra,omitempty"`
    SessionID   string         `json:"session_id,omitempty"`
    ClientID    string         `json:"client_id,omitempty"`
    RegisteredClaims
}
```

#### Field Descriptions

| Field         | Type             | Description                | Example                   |
|---------------|------------------|----------------------------|---------------------------|
| `UserID`      | `string`         | Unique user identifier     | `"user_12345"`            |
| `Username`    | `string`         | User display name          | `"john.doe"`              |
| `Role`        | `string`         | User role/permission level | `"admin"`, `"user"`       |
| `Permissions` | `[]string`       | Specific permissions       | `["read", "write"]`       |
| `Scopes`      | `[]string`       | OAuth-style scopes         | `["api:read", "profile"]` |
| `Extra`       | `map[string]any` | Custom fields              | `{"dept": "engineering"}` |
| `SessionID`   | `string`         | Session identifier         | `"sess_abc123"`           |
| `ClientID`    | `string`         | Client application ID      | `"web_client"`            |

### RegisteredClaims

Standard JWT claims as defined in RFC 7519.

```go
type RegisteredClaims struct {
    Issuer    string      `json:"iss,omitempty"`
    Subject   string      `json:"sub,omitempty"`
    Audience  []string    `json:"aud,omitempty"`
    ExpiresAt NumericDate `json:"exp,omitempty"`
    NotBefore NumericDate `json:"nbf,omitempty"`
    IssuedAt  NumericDate `json:"iat,omitempty"`
    ID        string      `json:"jti,omitempty"`
}
```

#### Field Descriptions

| Field       | Type          | Description       | Usage                  |
|-------------|---------------|-------------------|------------------------|
| `Issuer`    | `string`      | Token issuer      | Application identifier |
| `Subject`   | `string`      | Token subject     | User or resource ID    |
| `Audience`  | `[]string`    | Intended audience | Target services        |
| `ExpiresAt` | `NumericDate` | Expiration time   | Security control       |
| `NotBefore` | `NumericDate` | Not valid before  | Future activation      |
| `IssuedAt`  | `NumericDate` | Issue time        | Audit trail            |
| `ID`        | `string`      | Unique token ID   | Revocation support     |

### SigningMethod

Supported HMAC signing algorithms.

```go
type SigningMethod string

const (
    SigningMethodHS256 SigningMethod = "HS256"  // HMAC-SHA256 (recommended)
    SigningMethodHS384 SigningMethod = "HS384"  // HMAC-SHA384 (balanced)
    SigningMethodHS512 SigningMethod = "HS512"  // HMAC-SHA512 (maximum security)
)
```

#### Supported Algorithms

- **HS256** - HMAC-SHA256 (recommended for most use cases)
- **HS384** - HMAC-SHA384 (balanced security/performance)
- **HS512** - HMAC-SHA512 (maximum security)

### NumericDate

JWT timestamp type implementing RFC 7519 numeric date format.

```go
type NumericDate struct {
    time.Time
}

func NewNumericDate(t time.Time) NumericDate
```

#### Example
```go
claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(15 * time.Minute))
claims.IssuedAt = jwt.NewNumericDate(time.Now())
```
---

## ❌ Error Handling

### Error Constants

Pre-defined error constants for JWT operations.

```go
var (
    ErrInvalidConfig        = errors.New("invalid configuration")
    ErrInvalidSecretKey     = errors.New("invalid secret key")
    ErrInvalidSigningMethod = errors.New("invalid signing method")
    ErrInvalidToken         = errors.New("invalid token")
    ErrEmptyToken           = errors.New("empty token")
    ErrInvalidClaims        = errors.New("invalid claims")
    ErrRateLimitExceeded    = errors.New("rate limit exceeded")
    ErrTokenRevoked         = errors.New("token revoked")
    ErrProcessorClosed      = errors.New("processor closed")
)
```

### Error Handling Example

```go
token, err := jwt.CreateToken(secretKey, claims)
if err != nil {
    switch {
    case errors.Is(err, jwt.ErrInvalidSecretKey):
        return fmt.Errorf("invalid secret key")
    case errors.Is(err, jwt.ErrRateLimitExceeded):
        return fmt.Errorf("rate limit exceeded")
    default:
        return fmt.Errorf("token creation failed: %w", err)
    }
}
```

---

## 🔗 Related Documentation

- [Security Guide](SECURITY.md) - Security features and best practices
- [Performance Guide](PERFORMANCE.md) - Optimization techniques
- [Examples](EXAMPLES.md) - Integration examples
- [Best Practices](BEST_PRACTICES.md) - Production guidelines
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions
