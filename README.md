# JWT Library - High-Performance Go JWT Solution

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/cybergodev/jwt.svg)](https://pkg.go.dev/github.com/cybergodev/jwt)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Production%20Ready-green.svg)](docs/SECURITY.md)
[![Thread Safe](https://img.shields.io/badge/thread%20safe-yes-brightgreen.svg)](https://github.com/cybergodev/jwt)

A **production-ready Go JWT library** with a focus on security, performance, and ease of use. Provides a clean, struct-based configuration API with built-in token revocation and rate limiting.

**[中文文档](README_zh-CN.md)** | **[www.cybergo.dev/jwt](https://www.cybergo.dev/jwt)**

---

## Key Features

- **Simple API** - Create, validate, and revoke tokens with minimal code
- **Security Focused** - Input validation, rate limiting, token revocation, and secure key handling
- **Performance Optimized** - Object pooling and efficient memory management
- **Zero Dependencies** - Built entirely on Go standard library
- **Production Ready** - Thread-safe operations, configurable blacklist, and comprehensive error handling
- **Multiple Algorithms** - HMAC, RSA, RSA-PSS, and ECDSA signing methods supported

## Installation

Requires **Go 1.25** or later.

```bash
go get github.com/cybergodev/jwt
```

## Quick Start

### Minimal Configuration (HMAC)

The simplest way to use the library - start with `DefaultConfig()`:

```go
package main

import (
    "fmt"
    "log"

    "github.com/cybergodev/jwt"
)

func main() {
    // Start with DefaultConfig() for sensible defaults
    // Then customize only what you need
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~"

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    // Create user claims
    claims := jwt.Claims{
        UserID:      "user123",
        Username:    "john_doe",
        Role:        "admin",
        SessionID:   "session_12345",
        Permissions: []string{"read", "write"},
    }

    // Create token (pass pointer - Claims implements CustomClaims via pointer receiver)
    token, err := processor.Create(&claims)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Token:", token)

    // Validate token
    parsedClaims, valid, err := processor.Validate(token)
    if err != nil {
        log.Fatal(err)
    }
    if !valid {
        log.Fatal("Token is invalid")
    }
    fmt.Printf("User: %s, Role: %s\n", parsedClaims.Username, parsedClaims.Role)

    // Revoke token (add to blacklist)
    err = processor.Revoke(token)
    if err != nil {
        log.Printf("Revocation failed: %v", err)
    }
}
```

### Full Configuration (Recommended for Production)

For applications needing full configuration control:

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/cybergodev/jwt"
)

func main() {
    // Use DefaultConfig() as a starting point
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~"
    cfg.AccessTokenTTL = 15 * time.Minute
    cfg.RefreshTokenTTL = 7 * 24 * time.Hour
    cfg.Issuer = "my-app"
    cfg.SigningMethod = jwt.SigningMethodHS512

    // Optional: Enable rate limiting
    cfg.EnableRateLimit = true
    cfg.RateLimitRate = 100
    cfg.RateLimitWindow = time.Minute

    // Optional: Configure blacklist
    cfg.Blacklist = jwt.BlacklistConfig{
        MaxSize:           100000,
        CleanupInterval:   5 * time.Minute,
        EnableAutoCleanup: true,
    }

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
    }

    // Create access token (pass pointer)
    accessToken, err := processor.Create(&claims)
    if err != nil {
        log.Fatal(err)
    }

    // Create refresh token (longer TTL)
    refreshToken, err := processor.CreateRefresh(&claims)
    if err != nil {
        log.Fatal(err)
    }

    // Validate token
    parsedClaims, valid, err := processor.Validate(accessToken)
    if err != nil || !valid {
        log.Fatal("Invalid token")
    }
    fmt.Printf("User: %s\n", parsedClaims.Username)

    // Refresh access token using refresh token
    newAccessToken, err := processor.Refresh(refreshToken)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("New access token:", newAccessToken[:50]+"...")

    // Revoke token
    err = processor.Revoke(accessToken)
    if err != nil {
        log.Printf("Revocation failed: %v", err)
    }

    // Check if token is revoked
    isRevoked, err := processor.IsRevoked(accessToken)
    if err != nil {
        log.Printf("Check failed: %v", err)
    }
    fmt.Printf("Token revoked: %v\n", isRevoked)
}
```

### Asymmetric Signing (RSA/ECDSA)

For distributed systems requiring public/private key separation:

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "fmt"
    "log"

    "github.com/cybergodev/jwt"
)

func main() {
    // Generate RSA key pair (use 2048+ bits in production)
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal(err)
    }

    // Create processor with RSA private key
    cfg := jwt.DefaultConfig()
    cfg.SigningKey = privateKey           // *rsa.PrivateKey or *ecdsa.PrivateKey
    cfg.SigningMethod = jwt.SigningMethodRS256
    cfg.Issuer = "my-secure-service"

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
    }

    token, err := processor.Create(&claims)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("RSA Token:", token[:50]+"...")

    // Validate token
    parsedClaims, valid, err := processor.Validate(token)
    if err != nil || !valid {
        log.Fatal("Invalid token")
    }
    fmt.Printf("User: %s\n", parsedClaims.Username)
}
```

For ECDSA, replace the key generation and method:

```go
import "crypto/ecdsa"
import "crypto/elliptic"

privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
cfg.SigningKey = privateKey
cfg.SigningMethod = jwt.SigningMethodES256
```

> **VerificationKey**: For verification-only services, set `cfg.VerificationKey` to the public key. When set, verification uses `VerificationKey` instead of deriving the public key from `SigningKey`. See [Asymmetric Example](examples/5_asymmetric.go) for a complete demonstration.

### Custom Claims

For applications needing custom claim types:

```go
package main

import (
    "errors"
    "fmt"
    "log"

    "github.com/cybergodev/jwt"
)

// Define custom claims type
type MyClaims struct {
    UserID string   `json:"user_id"`
    TeamID string   `json:"team_id"`
    Roles  []string `json:"roles,omitempty"`
    jwt.RegisteredClaims
}

// Implement jwt.CustomClaims interface
func (c *MyClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
    return &c.RegisteredClaims
}

func (c *MyClaims) Validate() error {
    if c.UserID == "" {
        return errors.New("user_id is required")
    }
    return nil
}

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-super-secret-key-at-least-32-bytes-long!"

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    // Create token with custom claims
    claims := &MyClaims{
        UserID: "user123",
        TeamID: "team-abc",
        Roles:  []string{"admin", "developer"},
    }

    token, err := processor.Create(claims)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Token:", token[:50]+"...")

    // Validate token with custom claims
    parsedClaims := &MyClaims{}
    result, valid, err := processor.ValidateInto(token, parsedClaims)
    if err != nil || !valid {
        log.Fatal("Invalid token")
    }
    fmt.Printf("UserID: %s, TeamID: %s\n", result.(*MyClaims).UserID, result.(*MyClaims).TeamID)
}
```

## Configuration

### Configuration Options

```go
cfg := jwt.DefaultConfig()

// === Signing configuration (choose one) ===
cfg.SecretKey = "your-32-byte-secret-key-here............."  // For HMAC algorithms
cfg.SigningKey = privateKey                                  // For RSA/ECDSA (*rsa.PrivateKey or *ecdsa.PrivateKey)
cfg.VerificationKey = publicKey                              // Optional: public key for verification only
cfg.SigningMethod = jwt.SigningMethodHS256                   // See table below

// === Token settings ===
cfg.AccessTokenTTL = 15 * time.Minute
cfg.RefreshTokenTTL = 7 * 24 * time.Hour
cfg.Issuer = "my-app"
cfg.ExpectedAudience = "my-api"                              // Optional: reject tokens without matching aud

// === Blacklist settings (embedded in Config) ===
cfg.Blacklist = jwt.BlacklistConfig{
    MaxSize:           100000,        // Default: 100000
    CleanupInterval:   5 * time.Minute,  // Default: 5 * time.Minute
    EnableAutoCleanup: true,          // Default: true
    Store:             nil,           // Optional: custom BlacklistStore implementation
}

// === Rate limiting ===
cfg.EnableRateLimit = true
cfg.RateLimitRate = 100            // Max requests per window (Default: 100)
cfg.RateLimitWindow = time.Minute  // Per-user rate limit window (Default: 1 * time.Minute)
cfg.RateLimiter = nil              // Optional: custom RateLimitProvider implementation

// === Clock provider (optional, for testing) ===
cfg.Clock = jwt.FixedClock{T: time.Now()}  // Defaults to SystemClock

processor, err := jwt.New(cfg)
if err != nil {
    log.Fatal(err)
}
defer processor.Close()
```

### Supported Signing Methods

| Method | Type | Description |
|--------|------|-------------|
| `SigningMethodHS256` | HMAC | SHA-256 (default, recommended for HMAC) |
| `SigningMethodHS384` | HMAC | SHA-384 |
| `SigningMethodHS512` | HMAC | SHA-512 |
| `SigningMethodRS256` | RSA | SHA-256 (2048+ bit key) |
| `SigningMethodRS384` | RSA | SHA-384 |
| `SigningMethodRS512` | RSA | SHA-512 |
| `SigningMethodES256` | ECDSA | SHA-256 (P-256 curve) |
| `SigningMethodES384` | ECDSA | SHA-384 (P-384 curve) |
| `SigningMethodES512` | ECDSA | SHA-512 (P-521 curve) |

## Claims Structure

### Built-in Claims

```go
claims := jwt.Claims{
    // Custom fields
    UserID:      "user123",
    Username:    "john_doe",
    Role:        "admin",
    Permissions: []string{"read", "write"},
    Scopes:      []string{"api:read", "api:write"},
    SessionID:   "sess-abc123",
    ClientID:    "client-xyz789",

    // Extra fields (any additional data)
    Extra: map[string]any{
        "department": "engineering",
        "location":   "us-west",
    },

    // Standard JWT claims (embedded RegisteredClaims)
    // Issuer, Subject, Audience, ExpiresAt, NotBefore, IssuedAt, ID
}
```

> **Extra field restrictions**: Values in the `Extra` map support `string` and `[]string` types only. Nested maps and other types are rejected during validation. Maximum 50 keys per map.

### Registered Claims (Standard JWT)

| Field | JSON Key | Description |
|-------|----------|-------------|
| `Issuer` | `iss` | Token issuer |
| `Subject` | `sub` | Token subject |
| `Audience` | `aud` | Intended audience (accepts string or array) |
| `ExpiresAt` | `exp` | Expiration time |
| `NotBefore` | `nbf` | Not valid before |
| `IssuedAt` | `iat` | Issued at time |
| `ID` | `jti` | Unique token ID |

## HTTP Server Integration

### Gin Framework

```go
func JWTMiddleware(processor *jwt.Processor) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        token = strings.TrimPrefix(token, "Bearer ")

        claims, valid, err := processor.Validate(token)
        if err != nil || !valid {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("user", claims)
        c.Next()
    }
}
```

### Standard Library

```go
func loginHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims := jwt.Claims{
            UserID:   "user123",
            Username: "john_doe",
            Role:     "admin",
        }

        token, err := processor.Create(&claims)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        json.NewEncoder(w).Encode(map[string]string{
            "access_token": token,
            "token_type":   "Bearer",
        })
    }
}

func protectedHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")

        claims, valid, err := processor.Validate(tokenString)
        if err != nil || !valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "message": "Access granted",
            "user":    claims.Username,
            "role":    claims.Role,
        })
    }
}
```

## Security Features

### Input Validation
- **Secret Key Requirements**: Minimum 32 bytes with entropy validation
- **Claims Validation**: String length limits, array size limits, control character filtering
- **Pattern Detection**: Blocks suspicious patterns (XSS, SQL injection, path traversal)
- **Size Limits**: Maximum 256 bytes per string field, 100 items per array, 50 keys in Extra

### Token Security
- **Algorithm Verification**: Strict signing method validation (prevents algorithm confusion attacks)
- **Token Revocation**: Blacklist support with configurable cleanup
- **Expiration Enforcement**: Automatic validation of `exp`, `nbf`, and `iat` claims
- **Issuer/Audience Validation**: Optional issuer and audience claim verification

### Operational Security
- **Rate Limiting**: Token bucket algorithm with per-user limits
- **Thread Safety**: All operations are goroutine-safe
- **Secure Cleanup**: Secret keys are zeroed on processor close
- **Resource Limits**: Configurable blacklist size

## Error Handling

### Error Checking Pattern

```go
claims, valid, err := processor.Validate(token)
if err != nil {
    switch {
    case errors.Is(err, jwt.ErrTokenExpired):
        // Token has expired
    case errors.Is(err, jwt.ErrTokenRevoked):
        // Token was revoked
    case errors.Is(err, jwt.ErrInvalidToken):
        // Token is malformed or invalid signature
    case errors.Is(err, jwt.ErrRateLimitExceeded):
        // Rate limit exceeded
    case errors.Is(err, jwt.ErrTokenNotValidYet):
        // Token nbf claim is in the future
    case errors.Is(err, jwt.ErrTokenInvalidIssuer):
        // Token issuer does not match
    case errors.Is(err, jwt.ErrTokenInvalidAudience):
        // Token audience does not match
    case errors.Is(err, jwt.ErrInvalidClaims):
        // Claims validation failed
    default:
        // Other error
    }
}
```

### Available Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidConfig` | Configuration validation failed |
| `ErrInvalidSecretKey` | Secret key is too short or weak |
| `ErrInvalidSigningMethod` | Unsupported signing method |
| `ErrInvalidToken` | Token is malformed or signature invalid |
| `ErrEmptyToken` | Empty token string provided |
| `ErrAlgorithmMismatch` | Token algorithm does not match configured method |
| `ErrTokenRevoked` | Token exists in blacklist |
| `ErrTokenExpired` | Token has expired |
| `ErrTokenNotValidYet` | Token nbf claim is in the future |
| `ErrTokenInvalidIssuer` | Token issuer does not match |
| `ErrTokenInvalidAudience` | Token audience does not match |
| `ErrTokenMissingID` | Token missing jti claim |
| `ErrInvalidClaims` | Claims validation failed |
| `ErrRateLimitExceeded` | Rate limit exceeded |
| `ErrBlacklistNotConfigured` | Blacklist operation without configuration |
| `ErrProcessorClosed` | Processor has been closed |
| `ErrStoreClosed` | Store has been closed |

### Structured Error Types

For applications needing programmatic access to error details:

```go
// ValidationError - field-level validation failures (from claims deep validation)
var verr *jwt.ValidationError
if errors.As(err, &verr) {
    fmt.Println("Field:", verr.Field, "Issue:", verr.Message)
}
```

## API Reference

### Creating a Processor

```go
// Minimal - with default config
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key"
processor, err := jwt.New(cfg)

// Full configuration
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key"
cfg.Issuer = "my-app"
cfg.SigningMethod = jwt.SigningMethodHS512
processor, err := jwt.New(cfg)
```

### Processor Methods

| Method | Description |
|--------|-------------|
| `Create(claims CustomClaims) (string, error)` | Create access token |
| `Validate(token string) (Claims, bool, error)` | Validate token and return built-in Claims |
| `CreateRefresh(claims CustomClaims) (string, error)` | Create refresh token |
| `Refresh(refreshToken string) (string, error)` | Refresh access token |
| `ValidateInto(token string, claims CustomClaims) (CustomClaims, bool, error)` | Validate with custom claims type |
| `RefreshInto(refreshToken string, claims CustomClaims) (string, error)` | Refresh with custom claims type |
| `Revoke(token string) error` | Add token to blacklist |
| `IsRevoked(token string) (bool, error)` | Check if token is revoked |
| `ParseUnverified(token string, claims any) error` | Parse token without verification |
| `Close() error` | Release resources |
| `IsClosed() bool` | Check if processor is closed |

### CustomClaims Interface

```go
type CustomClaims interface {
    GetRegisteredClaims() *RegisteredClaims
    Validate() error
}
```

`*Claims` implements `CustomClaims` automatically. Pass `&claims` to methods accepting `CustomClaims`.

### Optional Interfaces

Custom claims types may implement `RateLimitKeyer` to provide a rate limit key when `Subject` is empty:

```go
type RateLimitKeyer interface {
    RateLimitKey() string
}
```

### Extensibility Interfaces

| Interface | Purpose |
|-----------|---------|
| `TokenManager` | Core token operations (implemented by `*Processor`) |
| `BlacklistStore` | Custom blacklist storage backend (e.g., Redis) |
| `RateLimitProvider` | Custom rate limiting implementation |
| `ClockProvider` | Time injection (use `SystemClock` or `FixedClock` for testing) |

#### Custom Blacklist Store Example

```go
// Implement BlacklistStore for Redis or other backends
type RedisStore struct {
    client *redis.Client
}

func (s *RedisStore) Add(tokenID string, expiresAt time.Time) error {
    return s.client.Set(ctx, "blacklist:"+tokenID, "1", time.Until(expiresAt)).Err()
}

func (s *RedisStore) Contains(tokenID string) (bool, error) {
    return s.client.Exists(ctx, "blacklist:"+tokenID).Result()
}

func (s *RedisStore) Close() error {
    return s.client.Close()
}

// Use in config
cfg.Blacklist = jwt.BlacklistConfig{
    Store: &RedisStore{client: rdb},
}
```

## Helper Types & Functions

| Symbol | Description |
|--------|-------------|
| `NumericDate` | JSON numeric date (Unix timestamp) for JWT time claims |
| `NewNumericDate(t time.Time) NumericDate` | Create NumericDate from time.Time |
| `StringOrSlice` | Audience claim type — accepts string or array per RFC 7519 |
| `RateLimiter` | Built-in token bucket rate limiter (implements `RateLimitProvider`) |
| `NewRateLimiter(maxRate int, window time.Duration) *RateLimiter` | Create a new rate limiter |
| `DefaultBlacklistConfig() BlacklistConfig` | Returns blacklist config with sensible defaults |

```go
// NumericDate for JWT time claims
expiresAt := jwt.NewNumericDate(time.Now().Add(time.Hour))

// StringOrSlice for audience claims
claims.Audience = jwt.StringOrSlice{"api-v1", "api-v2"}

// Standalone rate limiter
rl := jwt.NewRateLimiter(100, time.Minute)
rl.Allow("user:123")  // true/false
rl.Close()

// Default blacklist config
blCfg := jwt.DefaultBlacklistConfig()
// MaxSize: 100000, CleanupInterval: 5 * time.Minute, EnableAutoCleanup: true
```

## Detailed Documentation

| Documentation | Content | Use Case |
|---------------|---------|----------|
| [API Reference](docs/API.md) | Complete API documentation | Development reference |
| [Security Guide](docs/SECURITY.md) | Security features explained | Security audits |
| [Performance Guide](docs/PERFORMANCE.md) | Performance optimization tips | High-concurrency scenarios |
| [Integration Examples](docs/EXAMPLES.md) | Framework integration code | Project integration |
| [Best Practices](docs/BEST_PRACTICES.md) | Production environment guide | Deployment |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common problem solutions | Issue diagnosis |
| [Concurrency Guide](docs/CONCURRENCY.md) | Thread safety and patterns | Concurrent applications |

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

If this project helps you, please give it a Star!
