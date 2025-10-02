# JWT Library - Complete API Reference

> **High-Performance JWT Library** - Production-ready, secure JWT implementation with comprehensive API coverage

This document provides the complete API reference for the JWT library, including detailed function signatures, parameters, return values, practical examples, and production best practices.

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

> **Perfect for simple use cases** - These functions provide instant JWT operations with automatic processor caching and optimal performance.
>
> **⚡ No Rate Limiting** - Quick functions are designed for convenience and do not apply rate limiting, making them ideal for internal services and trusted environments.

### CreateToken

Creates a JWT token using an optimized cached processor. Ideal for applications that need simple token creation without complex configuration.

```go
func CreateToken(secretKey string, claims Claims) (string, error)
```

#### Parameters
| Parameter | Type | Description | Requirements |
|-----------|------|-------------|--------------|
| `secretKey` | `string` | Cryptographic secret key | ≥32 bytes, high entropy |
| `claims` | `Claims` | JWT payload data | Valid claims structure |

#### Returns
| Type | Description |
|------|-------------|
| `string` | Base64-encoded JWT token |
| `error` | Error details or `nil` on success |

#### Example: Basic Token Creation
```go
// Define user claims
claims := jwt.Claims{
    UserID:   "user_12345",
    Username: "john.doe",
    Role:     "admin",
    Permissions: []string{"read", "write", "delete"},
}

// Set token expiration time (default 15 minutes) - when token expires
claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Minute))

// Create token (processor automatically cached)
secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-g!"
token, err := jwt.CreateToken(secretKey, claims)
if err != nil {
    log.Panicf("token creation failed: %v", err)
}

fmt.Printf("Generated token: %s\n", token)
```

#### Example: Production Usage with Error Handling
```go
func generateUserToken(userID, role string, permissions []string) (string, error) {
    claims := jwt.Claims{
        UserID:      userID,
        Role:        role,
        Permissions: permissions,
    }

    // Set token expiration time (default 15 minutes) - when token expires
    claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Minute))

    token, err := jwt.CreateToken(os.Getenv("JWT_SECRET"), claims)
    if err != nil {
        log.Printf("Token generation failed for user %s: %v", userID, err)
        return "", fmt.Errorf("authentication token generation failed")
    }

    return token, nil
}
```

### ValidateToken

Validates a JWT token with comprehensive security checks including signature verification, expiration, and blacklist validation.

```go
func ValidateToken(secretKey, tokenString string) (*Claims, bool, error)
```

#### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `secretKey` | `string` | Same secret key used for token creation |
| `tokenString` | `string` | JWT token to validate |

#### Returns
| Type | Description |
|------|-------------|
| `*Claims` | Parsed and validated claims (nil if invalid) |
| `bool` | `true` if token is valid and not expired |
| `error` | Validation error details or `nil` |

#### Example: Basic Token Validation
```go
claims, valid, err := jwt.ValidateToken(secretKey, tokenString)
if err != nil {
    log.Printf("Token validation error: %v", err)
    return http.StatusUnauthorized, "Invalid token"
}

if !valid {
    log.Println("Token is expired or invalid")
    return http.StatusUnauthorized, "Token expired"
}

// Token is valid - use claims
fmt.Printf("Authenticated user: %s (Role: %s)\n", claims.Username, claims.Role)
```

#### Example: Middleware Implementation
```go
func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract token from Authorization header
        authHeader := r.Header.Get("Authorization")
        if !strings.HasPrefix(authHeader, "Bearer ") {
            http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")

        // Validate token
        claims, valid, err := jwt.ValidateToken(os.Getenv("JWT_SECRET"), token)
        if err != nil || !valid {
            http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
            return
        }

        // Add claims to request context
        ctx := context.WithValue(r.Context(), "user_claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}
```

### RevokeToken

Immediately revokes a JWT token by adding it to the blacklist, preventing future use even if not expired.

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

#### Example: User Logout
```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    token := extractTokenFromRequest(r)
    if token == "" {
        http.Error(w, "No token provided", http.StatusBadRequest)
        return
    }

    // Revoke the token
    if err := jwt.RevokeToken(os.Getenv("JWT_SECRET"), token); err != nil {
        log.Printf("Token revocation failed: %v", err)
        http.Error(w, "Logout failed", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}
```

#### Example: Security Incident Response
```go
func emergencyRevokeUserTokens(userID string) error {
    // In a real implementation, you'd track user tokens
    // This is a simplified example
    tokens := getUserActiveTokens(userID) // Your implementation

    var errors []error
    for _, token := range tokens {
        if err := jwt.RevokeToken(os.Getenv("JWT_SECRET"), token); err != nil {
            errors = append(errors, fmt.Errorf("failed to revoke token: %w", err))
        }
    }

    if len(errors) > 0 {
        return fmt.Errorf("some tokens could not be revoked: %v", errors)
    }

    return nil
}
```

---

## 🏭 Processor API

> **Advanced control and configuration** - The Processor API provides fine-grained control over JWT operations with custom configurations, blacklist management, and performance optimization.
>
> **🛡️ Configurable Rate Limiting** - Processor mode supports optional rate limiting to protect against abuse and ensure system stability in production environments.

### New

Creates a new JWT processor with default configuration. Use this for most applications that need basic JWT functionality.

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

The processor supports configurable rate limiting through the Config structure. Rate limiting is disabled by default and can be enabled as needed.

#### Config Structure
```go
type Config struct {
    SecretKey       string
    AccessTokenTTL  time.Duration
    RefreshTokenTTL time.Duration
    Issuer          string
    SigningMethod   SigningMethod
    Timezone        *time.Location
    EnableRateLimit bool             // Enable rate limiting (default: false)
    RateLimit       *RateLimitConfig // Optional rate limiting configuration
}
```

#### Example: Processor with Rate Limiting
```go
// Configure rate limits for production API
rateLimitConfig := jwt.RateLimitConfig{
    Enabled:           true,
    TokenCreationRate: 100,   // 100 tokens per minute per user
    ValidationRate:    1000,  // 1000 validations per minute per user
    LoginAttemptRate:  5,     // 5 login attempts per minute per IP
    PasswordResetRate: 3,     // 3 password resets per hour per user
    CleanupInterval:   5 * time.Minute,
}

// Create config with rate limiting enabled
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimit = &rateLimitConfig

processor, err := jwt.New(secretKey, config)
if err != nil {
    log.Fatalf("Rate limited processor creation failed: %v", err)
}
defer processor.Close()

// This will be rate limited
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    // Handle rate limit exceeded
    return errors.New("too many requests, please try again later")
}
```

#### Example: Processor without Rate Limiting
```go
// For internal microservices communication
config := jwt.DefaultConfig()
config.EnableRateLimit = false // Explicitly disable (default behavior)

processor, err := jwt.New(secretKey, config)
if err != nil {
    log.Fatalf("Processor creation failed: %v", err)
}
defer processor.Close()

// No rate limiting applied
for i := 0; i < 1000; i++ {
    token, err := processor.CreateToken(claims)
    // Will not hit rate limits
}
```

#### Example: Production Setup with Rate Limiting and Blacklist
```go
// Maximum security configuration
rateLimitConfig := jwt.RateLimitConfig{
    Enabled:           true,
    TokenCreationRate: 50,    // Conservative limits
    ValidationRate:    500,
    LoginAttemptRate:  3,     // Strict login protection
    PasswordResetRate: 1,     // Very strict password reset
    CleanupInterval:   2 * time.Minute,
}

blacklistConfig := jwt.BlacklistConfig{
    MaxSize:           50000,
    CleanupInterval:   3 * time.Minute,
    EnableAutoCleanup: true,
    StoreType:        "memory",
}

config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimit = &rateLimitConfig

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
if err != nil {
    log.Fatalf("Secure processor creation failed: %v", err)
}
defer processor.Close()

// Both rate limiting and token revocation available
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    return errors.New("rate limit exceeded")
}

// Later, revoke the token
err = processor.RevokeToken(token)
```

### Processor.CreateToken

Creates a JWT token with the processor's configuration. Provides better performance than convenience functions for high-throughput applications.

```go
func (p *Processor) CreateToken(claims Claims) (string, error)
```

#### Parameters
| Parameter | Type     | Description      |
|-----------|----------|------------------|
| `claims`  | `Claims` | JWT payload data |

#### Returns
| Type     | Description      |
|----------|------------------|
| `string` | Signed JWT token |
| `error`  | Creation error   |

#### Example: High-Performance Token Creation
```go
// Optimized for high throughput
func createUserSession(processor *jwt.Processor, userID, role string) (string, error) {
    claims := jwt.Claims{
        UserID:    userID,
        Role:      role,
    }

    // Set token expiration time (default 15 minutes) - when token expires
    claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Minute))

    return processor.CreateToken(claims)
}
```

### Processor.CreateTokenWithContext

Creates a JWT token with context support for cancellation and timeouts. Ideal for web applications with request timeouts.

```go
func (p *Processor) CreateTokenWithContext(ctx context.Context, claims Claims) (string, error)
```

#### Parameters
| Parameter | Type              | Description                      |
|-----------|-------------------|----------------------------------|
| `ctx`     | `context.Context` | Request context for cancellation |
| `claims`  | `Claims`          | JWT payload data                 |

#### Returns
| Type     | Description               |
|----------|---------------------------|
| `string` | Signed JWT token          |
| `error`  | Creation or context error |

#### Example: Web Handler with Timeout
```go
func loginHandler(processor *jwt.Processor, w http.ResponseWriter, r *http.Request) {
    // Create context with timeout
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    // Extract user info from request
    userID := getUserIDFromRequest(r)
    role := getUserRoleFromDB(userID)

    claims := jwt.Claims{
        UserID: userID,
        Role:   role,
    }

    // Create token with context
    token, err := processor.CreateTokenWithContext(ctx, claims)
    if err != nil {
        if errors.Is(err, context.DeadlineExceeded) {
            http.Error(w, "Request timeout", http.StatusRequestTimeout)
            return
        }
        http.Error(w, "Token creation failed", http.StatusInternalServerError)
        return
    }

    // Return token
    json.NewEncoder(w).Encode(map[string]string{"token": token})
}
```

### Processor.ValidateToken

Validates a JWT token using the processor's configuration with comprehensive security checks.

```go
func (p *Processor) ValidateToken(tokenString string) (*Claims, bool, error)
```

#### Parameters
| Parameter     | Type     | Description           |
|---------------|----------|-----------------------|
| `tokenString` | `string` | JWT token to validate |

#### Returns
| Type      | Description                              |
|-----------|------------------------------------------|
| `*Claims` | Parsed claims (nil if invalid)           |
| `bool`    | `true` if token is valid and not expired |
| `error`   | Validation error details                 |

#### Example: API Authentication
```go
func authenticateRequest(processor *jwt.Processor, token string) (*jwt.Claims, error) {
    claims, valid, err := processor.ValidateToken(token)
    if err != nil {
        return nil, fmt.Errorf("token validation failed: %w", err)
    }

    if !valid {
        return nil, fmt.Errorf("token is invalid or expired")
    }

    return claims, nil
}
```

### Processor.ValidateTokenWithContext

Validates a JWT token with context support for request cancellation and timeout handling.

```go
func (p *Processor) ValidateTokenWithContext(ctx context.Context, tokenString string) (*Claims, bool, error)
```

#### Parameters
| Parameter     | Type              | Description           |
|---------------|-------------------|-----------------------|
| `ctx`         | `context.Context` | Request context       |
| `tokenString` | `string`          | JWT token to validate |

#### Returns
| Type      | Description                    |
|-----------|--------------------------------|
| `*Claims` | Parsed claims (nil if invalid) |
| `bool`    | `true` if token is valid       |
| `error`   | Validation or context error    |

### Processor.CreateRefreshToken

Creates a long-lived refresh token using the configured RefreshTokenTTL. Used in token refresh workflows.

```go
func (p *Processor) CreateRefreshToken(claims Claims) (string, error)
```

#### Parameters
| Parameter | Type     | Description                   |
|-----------|----------|-------------------------------|
| `claims`  | `Claims` | JWT payload for refresh token |

#### Returns
| Type     | Description              |
|----------|--------------------------|
| `string` | Long-lived refresh token |
| `error`  | Creation error           |

#### Example: Login with Refresh Token
```go
func loginUser(processor *jwt.Processor, userID, role string) (accessToken, refreshToken string, err error) {
    claims := jwt.Claims{
        UserID: userID,
        Role:   role,
    }

    // Create short-lived access token
    accessToken, err = processor.CreateToken(claims)
    if err != nil {
        return "", "", fmt.Errorf("access token creation failed: %w", err)
    }

    // Create long-lived refresh token
    refreshToken, err = processor.CreateRefreshToken(claims)
    if err != nil {
        return "", "", fmt.Errorf("refresh token creation failed: %w", err)
    }

    return accessToken, refreshToken, nil
}
```

### Processor.RefreshToken

Creates a new access token from a valid refresh token. Essential for seamless user experience without frequent re-authentication.

```go
func (p *Processor) RefreshToken(refreshTokenString string) (string, error)
```

#### Parameters
| Parameter            | Type     | Description         |
|----------------------|----------|---------------------|
| `refreshTokenString` | `string` | Valid refresh token |

#### Returns
| Type     | Description                                   |
|----------|-----------------------------------------------|
| `string` | New access token with fresh expiration        |
| `error`  | Refresh error (invalid/expired refresh token) |

#### Example: Token Refresh Endpoint
```go
func refreshTokenHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            RefreshToken string `json:"refresh_token"`
        }

        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request body", http.StatusBadRequest)
            return
        }

        // Generate new access token
        newAccessToken, err := processor.RefreshToken(req.RefreshToken)
        if err != nil {
            http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
            return
        }

        // Return new access token
        response := map[string]string{
            "access_token": newAccessToken,
            "token_type":   "Bearer",
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}
```

### Processor.RevokeToken

Immediately revokes a JWT token by adding it to the blacklist, preventing future use.

```go
func (p *Processor) RevokeToken(tokenString string) error
```

#### Parameters
| Parameter     | Type     | Description         |
|---------------|----------|---------------------|
| `tokenString` | `string` | JWT token to revoke |

#### Returns
| Type    | Description                        |
|---------|------------------------------------|
| `error` | Revocation error or nil on success |

### Processor.Close

Securely closes the processor and cleans up all resources including memory wiping of sensitive data.

```go
func (p *Processor) Close() error
```

#### Returns
| Type    | Description                     |
|---------|---------------------------------|
| `error` | Cleanup error or nil on success |

#### Example: Graceful Shutdown
```go
func main() {
    processor, err := jwt.New(secretKey)
    if err != nil {
        log.Fatal(err)
    }

    // Ensure cleanup on shutdown
    defer func() {
        if err := processor.Close(); err != nil {
            log.Printf("Processor cleanup failed: %v", err)
        }
    }()

    // Handle shutdown signals
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-c
        log.Println("Shutting down gracefully...")
        processor.Close()
        os.Exit(0)
    }()

    // Application logic...
}
```

---

## ⚙️ Configuration

> **Setup and customization** - Comprehensive configuration options for JWT processors with security-focused defaults and production-ready settings.

### Config

Main configuration structure for JWT processors with comprehensive security and performance options.

```go
type Config struct {
    SecretKey       string
    AccessTokenTTL  time.Duration
    RefreshTokenTTL time.Duration
    Issuer          string
    SigningMethod   SigningMethod
    Timezone        *time.Location
    EnableRateLimit bool
    RateLimit       *RateLimitConfig
}
```

#### Configuration Fields

| Field             | Type               | Description                 | Default         | Requirements            |
|-------------------|--------------------|-----------------------------|-----------------|-------------------------|
| `SecretKey`       | `string`           | Cryptographic secret key    | `""`            | ≥32 bytes, high entropy |
| `AccessTokenTTL`  | `time.Duration`    | Access token lifetime       | `15m`           | > 0, < RefreshTokenTTL  |
| `RefreshTokenTTL` | `time.Duration`    | Refresh token lifetime      | `168h` (7 days) | > AccessTokenTTL        |
| `Issuer`          | `string`           | Token issuer identifier     | `"jwt-service"` | Non-empty string        |
| `SigningMethod`   | `SigningMethod`    | HMAC algorithm              | `HS256`         | HS256/HS384/HS512       |
| `Timezone`        | `*time.Location`   | Timestamp timezone          | `time.Local`    | Valid timezone          |
| `EnableRateLimit` | `bool`             | Enable rate limiting        | `false`         | Boolean flag            |
| `RateLimit`       | `*RateLimitConfig` | Rate limiting configuration | `nil`           | Valid when enabled      |

### DefaultConfig

Returns a secure default configuration optimized for production use.

```go
func DefaultConfig() Config
```

#### Returns
| Type     | Description                            |
|----------|----------------------------------------|
| `Config` | Production-ready default configuration |

#### Example: Production Configuration
```go
// Start with secure defaults
config := jwt.DefaultConfig()

// Customize for your application
config.SecretKey = os.Getenv("JWT_SECRET_KEY")  // From environment
config.AccessTokenTTL = 10 * time.Minute        // Short-lived for security
config.RefreshTokenTTL = 24 * time.Hour         // Daily refresh
config.Issuer = "myapp-production-v1.2"         // Version-specific issuer
config.SigningMethod = jwt.SigningMethodHS512   // Stronger algorithm

// Validate before use
if err := config.Validate(); err != nil {
    log.Fatalf("Invalid configuration: %v", err)
}
```

### Config.Validate

Validates configuration for security compliance and logical consistency.

```go
func (c *Config) Validate() error
```

#### Returns
| Type    | Description                              |
|---------|------------------------------------------|
| `error` | Validation error details or nil if valid |

#### Validation Rules
- **Secret Key**: Minimum 32 bytes, entropy validation, weak key detection
- **TTL Values**: Positive durations, AccessTokenTTL < RefreshTokenTTL
- **Signing Method**: Must be supported algorithm (HS256/HS384/HS512)
- **Issuer**: Non-empty string identifier

### BlacklistConfig

Configuration for token revocation and blacklist management.

```go
type BlacklistConfig struct {
    MaxSize           int           `yaml:"max_size" json:"max_size"`
    CleanupInterval   time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
    EnableAutoCleanup bool          `yaml:"enable_auto_cleanup" json:"enable_auto_cleanup"`
    StoreType         string        `yaml:"store_type" json:"store_type"`
}
```

#### Configuration Fields

| Field               | Type            | Description                          | Default    | Recommendations              |
|---------------------|-----------------|--------------------------------------|------------|------------------------------|
| `MaxSize`           | `int`           | Maximum revoked tokens to store      | `10000`    | Scale based on user base     |
| `CleanupInterval`   | `time.Duration` | Expired entry cleanup frequency      | `5m`       | Balance memory vs CPU        |
| `EnableAutoCleanup` | `bool`          | Automatic cleanup of expired entries | `true`     | Always enable for production |
| `StoreType`         | `string`        | Storage backend type                 | `"memory"` | "memory" for single instance |

### DefaultBlacklistConfig

Returns optimized blacklist configuration for production use.

```go
func DefaultBlacklistConfig() BlacklistConfig
```

#### Example: High-Volume Configuration
```go
// For high-traffic applications
blacklistConfig := jwt.BlacklistConfig{
    MaxSize:           100000,           // 100K revoked tokens
    CleanupInterval:   2 * time.Minute,  // Frequent cleanup
    EnableAutoCleanup: true,             // Essential for memory management
    StoreType:        "memory",          // Fast in-memory storage
}
```

### RateLimitConfig

Configuration for DoS protection and rate limiting controls.

```go
type RateLimitConfig struct {
    Enabled           bool          `yaml:"enabled" json:"enabled"`
    TokenCreationRate int           `yaml:"token_creation_rate" json:"token_creation_rate"`
    ValidationRate    int           `yaml:"validation_rate" json:"validation_rate"`
    LoginAttemptRate  int           `yaml:"login_attempt_rate" json:"login_attempt_rate"`
    PasswordResetRate int           `yaml:"password_reset_rate" json:"password_reset_rate"`
    CleanupInterval   time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
}
```

#### Configuration Fields

| Field               | Type            | Description               | Default | Recommendations              |
|---------------------|-----------------|---------------------------|---------|------------------------------|
| `Enabled`           | `bool`          | Enable rate limiting      | `true`  | Always enable for production |
| `TokenCreationRate` | `int`           | Tokens per minute limit   | `100`   | Adjust based on user load    |
| `ValidationRate`    | `int`           | Validations per minute    | `1000`  | High limit for API calls     |
| `LoginAttemptRate`  | `int`           | Login attempts per minute | `5`     | Prevent brute force attacks  |
| `PasswordResetRate` | `int`           | Password resets per hour  | `3`     | Prevent abuse                |
| `CleanupInterval`   | `time.Duration` | Cleanup frequency         | `5m`    | Balance memory vs CPU        |

#### Example: Production Rate Limiting
```go
// High-security rate limiting
rateLimitConfig := jwt.RateLimitConfig{
    Enabled:           true,
    TokenCreationRate: 200,              // Allow burst traffic
    ValidationRate:    5000,             // High API throughput
    LoginAttemptRate:  3,                // Strict login security
    PasswordResetRate: 2,                // Conservative reset policy
    CleanupInterval:   2 * time.Minute,  // Frequent cleanup
}
```

---

## 📊 Data Types

> **Core data structures** - Essential types for JWT operations with comprehensive field descriptions and usage examples.

### Claims

Main JWT claims structure with custom fields and embedded standard claims.

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

#### Algorithm Comparison

| Algorithm | Security | Performance | Key Size | Recommendation                |
|-----------|----------|-------------|----------|-------------------------------|
| **HS256** | High     | Fastest     | 256-bit  | **Production default**        |
| **HS384** | Higher   | Fast        | 384-bit  | Balanced security/performance |
| **HS512** | Highest  | Good        | 512-bit  | Maximum security applications |

### NumericDate

JWT timestamp type implementing RFC 7519 numeric date format.

```go
type NumericDate struct {
    time.Time
}
```

#### NewNumericDate

Creates a new NumericDate from time.Time with timezone handling.

```go
func NewNumericDate(t time.Time) NumericDate
```

#### Parameters
| Parameter | Type        | Description           |
|-----------|-------------|-----------------------|
| `t`       | `time.Time` | Time value to convert |

#### Returns
| Type          | Description              |
|---------------|--------------------------|
| `NumericDate` | JWT-compatible timestamp |

#### Example Usage
```go
// Set expiration 15 minutes from now
expiresAt := jwt.NewNumericDate(time.Now().Add(15 * time.Minute))

// Set issued at current time
issuedAt := jwt.NewNumericDate(time.Now())

// Use in claims
claims := jwt.Claims{
    UserID: "user123",
    RegisteredClaims: jwt.RegisteredClaims{
        ExpiresAt: expiresAt,
        IssuedAt:  issuedAt,
        Issuer:    "my-app",
    },
}
```
---

## ❌ Error Handling

> **Comprehensive error management** - Complete error types and handling patterns for robust JWT operations.

### Error Constants

Pre-defined error constants for common JWT operations.

```go
var (
    // Configuration errors
    ErrInvalidConfig        = errors.New("invalid configuration")
    ErrInvalidSecretKey     = errors.New("invalid secret key")
    ErrInvalidSigningMethod = errors.New("invalid signing method")

    // Token errors
    ErrInvalidToken = errors.New("invalid token")
    ErrEmptyToken   = errors.New("empty token")

    // Claims errors
    ErrInvalidClaims = errors.New("invalid claims")

    // System errors
    ErrRateLimitExceeded = errors.New("rate limit exceeded")
)
```

#### Error Categories

| Category          | Errors                                    | Description                    | HTTP Status |
|-------------------|-------------------------------------------|--------------------------------|-------------|
| **Configuration** | `ErrInvalidConfig`, `ErrInvalidSecretKey` | Setup and configuration issues | 500         |
| **Token**         | `ErrInvalidToken`, `ErrEmptyToken`        | Token format and validation    | 401         |
| **Claims**        | `ErrInvalidClaims`                        | Claims validation failures     | 400         |
| **System**        | `ErrRateLimitExceeded`                    | System resource limits         | 429         |

### ValidationError

Structured validation error with field-level details.

```go
type ValidationError struct {
    Field   string  // Field that failed validation
    Message string  // Human-readable error message
    Err     error   // Underlying error (optional)
}
```

#### Methods

| Method           | Description                               | Returns       |
|------------------|-------------------------------------------|---------------|
| `Error() string` | Returns formatted error message           | Error string  |
| `Unwrap() error` | Returns underlying error for error chains | Wrapped error |

### Error Handling Patterns

#### Basic Error Handling
```go
token, err := jwt.CreateToken(secretKey, claims)
if err != nil {
    switch {
    case errors.Is(err, jwt.ErrInvalidSecretKey):
        log.Fatal("Invalid secret key configuration")
    case errors.Is(err, jwt.ErrInvalidClaims):
        http.Error(w, "Invalid claims", http.StatusBadRequest)
    default:
        http.Error(w, "Token creation failed", http.StatusInternalServerError)
    }
    return
}
```

#### Advanced Error Handling with Validation Errors
```go
claims, valid, err := jwt.ValidateToken(secretKey, tokenString)
if err != nil {
    var validationErr *jwt.ValidationError
    if errors.As(err, &validationErr) {
        log.Printf("Validation failed for field %s: %s", validationErr.Field, validationErr.Message)
        http.Error(w, fmt.Sprintf("Invalid %s", validationErr.Field), http.StatusBadRequest)
        return
    }

    // Handle other error types
    http.Error(w, "Token validation failed", http.StatusUnauthorized)
    return
}
```

---

## 🎯 API Usage Guidelines

### 🚀 Performance Recommendations

| Scenario                         | Recommended API       | Reason                                   |
|----------------------------------|-----------------------|------------------------------------------|
| **High-throughput applications** | Processor API         | Eliminates processor creation overhead   |
| **Simple applications**          | Quick Functions       | Automatic caching and optimization       |
| **Microservices**                | Processor per service | Isolated configuration and resources     |
| **Web applications**             | Context-aware methods | Request timeout and cancellation support |

### 🔒 Security Best Practices

1. **Secret Key Management**
   ```go
   // ✅ DO: Use environment variables
   secretKey := os.Getenv("JWT_SECRET_KEY")

   // ❌ DON'T: Hardcode secrets
   secretKey := "hardcoded-secret"
   ```

2. **Token Lifecycle Management**
   ```go
   // ✅ DO: Use short-lived access tokens with refresh tokens
   config := jwt.Config{
       AccessTokenTTL:  15 * time.Minute,   // Short-lived
       RefreshTokenTTL: 7 * 24 * time.Hour, // Weekly refresh
   }
   ```

3. **Resource Cleanup**
   ```go
   // ✅ DO: Always close processors
   processor, err := jwt.New(secretKey)
   if err != nil {
       return err
   }
   defer processor.Close() // Essential for security
   ```

### 📊 Performance Benchmarks

Based on the latest benchmarks:
- **Token Creation**: ~85,000 ops/sec (13.8μs/op)
- **Token Validation**: ~90,000 ops/sec (11.1μs/op)
- **Memory Usage**: 3.7KB per operation with 45 allocations
- **Concurrent Performance**: Linear scaling up to CPU cores

### 🔗 Related Documentation

- **[Security Guide](SECURITY.md)** - Comprehensive security features and best practices
- **[Performance Guide](PERFORMANCE.md)** - Optimization techniques and benchmarks
- **[Examples](EXAMPLES.md)** - Real-world integration examples
- **[Best Practices](BEST_PRACTICES.md)** - Production deployment guidelines
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues and solutions

---

**📚 This API reference provides complete coverage of the JWT library's functionality. For additional help, consult the related documentation or review the comprehensive examples.**
