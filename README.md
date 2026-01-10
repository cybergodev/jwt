# JWT Library - High-Performance Go JWT Solution

[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/cybergodev/jwt.svg)](https://pkg.go.dev/github.com/cybergodev/jwt)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Production%20Ready-green.svg)](docs/SECURITY.md)
[![Thread Safe](https://img.shields.io/badge/thread%20safe-yes-brightgreen.svg)](https://github.com/cybergodev/json)

A **production-ready Go JWT library** with a focus on security, performance, and ease of use. Provides both simple convenience functions and advanced processor patterns for flexible JWT operations with built-in token revocation and rate limiting.

### **[📖 中文文档](README_zh_CN.md)** - User guide

---

## 🎯 Key Features

- ⚡ **Minimal API** - Only 3 convenience functions: `CreateToken`, `ValidateToken`, `RevokeToken`
- 🛡️ **Security Focused** - Input validation, rate limiting, token revocation, and secure key handling
- 🚀 **Performance Optimized** - Object pooling, processor caching, and efficient memory management
- 📦 **Zero Dependencies** - Built entirely on Go standard library
- 🔧 **Production Ready** - Thread-safe operations, configurable blacklist, and comprehensive error handling
- 🌟 **Flexible Architecture** - Simple convenience API or advanced processor pattern with rate limiting

## 📦 Installation

```bash
go get github.com/cybergodev/jwt
```

## ⚡ 5-Minute Quick Start

### 1️⃣ Create Token
```go
package main

import (
    "fmt"
    "time"

    "github.com/cybergodev/jwt"
)

func main() {
    // Set secret key (recommend using environment variables in production)
    secretKey := "your-super-secret-key-at-least-32-bytes-long!"

    // Create user claims
    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
        Permissions: []string{"read", "write"},
    }

    // Set token expiration time (2 hours in this example)
    claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Hour))

    // Create token - it's that simple!
    token, err := jwt.CreateToken(secretKey, claims)
    if err != nil {
        panic(err)
    }

    fmt.Println("Token:", token)
}
```

### 2️⃣ Validate Token
```go
// Validate token
claims, valid, err := jwt.ValidateToken(secretKey, token)
if err != nil {
    fmt.Printf("Validation failed: %v\n", err)
    return
}

if !valid {
    fmt.Println("Token is invalid")
    return
}

fmt.Printf("User: %s, Role: %s\n", claims.Username, claims.Role)
```

### 3️⃣ Revoke Token
```go
// Revoke token (add to blacklist)
err = jwt.RevokeToken(secretKey, token)
if err != nil {
    fmt.Printf("Revocation failed: %v\n", err)
}
```

## 🏗️ Advanced Usage

### Processor Pattern (Recommended for Production)
The processor pattern provides better resource management, custom configuration, and optional rate limiting.

```go
// Create processor with default configuration
processor, err := jwt.New(secretKey)
if err != nil {
    panic(err)
}
defer processor.Close() // Always close to release resources

// Create access token
token, err := processor.CreateToken(claims)

// Validate token
claims, valid, err := processor.ValidateToken(token)

// Revoke token (add to blacklist)
err = processor.RevokeToken(token)

// Check if token is revoked
isRevoked, err := processor.IsTokenRevoked(token)

// Create refresh token (longer TTL)
refreshToken, err := processor.CreateRefreshToken(claims)

// Use refresh token to get new access token
newToken, err := processor.RefreshToken(refreshToken)

// Create processor with custom blacklist configuration
blacklistConfig := jwt.DefaultBlacklistConfig()
processor, err = jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

### Custom Configuration
```go
// Configure token TTLs and signing method
config := jwt.Config{
    AccessTokenTTL:  15 * time.Minute,       // Short-lived access tokens
    RefreshTokenTTL: 7 * 24 * time.Hour,     // Long-lived refresh tokens
    Issuer:          "your-app",             // Token issuer identifier
    SigningMethod:   jwt.SigningMethodHS256, // HS256, HS384, or HS512
}

// Configure blacklist behavior
blacklistConfig := jwt.BlacklistConfig{
    MaxSize:           10000,             // Maximum number of blacklisted tokens
    CleanupInterval:   5 * time.Minute,   // How often to clean expired entries
    EnableAutoCleanup: true,              // Automatically remove expired tokens
}

// Create processor with both configurations
processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
if err != nil {
    panic(err)
}
defer processor.Close()
```

## 🌟 Architecture Overview

| Component                    | Description                                      | Use Case                                |
|------------------------------|--------------------------------------------------|-----------------------------------------|
| 🎯 **Convenience Functions** | Simple 3-function API with internal caching     | Quick prototyping, simple applications  |
| 🔧 **Processor Pattern**     | Configurable, resource-managed JWT operations   | Production apps, custom requirements    |
| 🛡️ **Security Features**     | Input validation, rate limiting, token blacklist | Protecting against common JWT attacks   |
| ⚡ **Performance**            | Object pooling, processor caching               | High-throughput applications            |
| 📦 **Zero Dependencies**     | Standard library only                           | Minimal attack surface, easy auditing   |

## 🎛️ Rate Limiting

The library provides flexible rate limiting through the processor pattern:

### Convenience Functions (No Rate Limiting)
The convenience functions (`CreateToken`, `ValidateToken`, `RevokeToken`) use internal processor caching and do not enforce rate limits. Suitable for:
- Internal services
- Trusted environments
- Development and testing

```go
// No rate limiting applied
token, err := jwt.CreateToken(secretKey, claims)
claims, valid, err := jwt.ValidateToken(secretKey, token)
err = jwt.RevokeToken(secretKey, token)
```

### Processor with Rate Limiting
Enable rate limiting for public-facing APIs:

```go
// Configure rate limiting
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100           // Maximum 100 tokens per window
config.RateLimitWindow = time.Minute // Per-user rate limit window

// Create processor with rate limiting
processor, err := jwt.New(secretKey, config)
if err != nil {
    panic(err)
}
defer processor.Close()

// Operations are rate-limited per UserID
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    // User has exceeded rate limit
    log.Printf("Rate limit exceeded for user: %s", claims.UserID)
}
```

### Production Configuration
Combine rate limiting with blacklist management:

```go
// Full production configuration
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100
config.RateLimitWindow = time.Minute

blacklistConfig := jwt.DefaultBlacklistConfig()

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
if err != nil {
    panic(err)
}
defer processor.Close()

// Both rate limiting and token revocation are active
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    // Handle rate limit
}

err = processor.RevokeToken(token)
if err != nil {
    // Handle revocation error
}
```

## 🔗 HTTP Server Integration - Simple Examples

### Gin Framework Example
```go
func JWTMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        token = strings.TrimPrefix(token, "Bearer ")

        // Validate JWT Token
        claims, valid, err := jwt.ValidateToken(secretKey, token)
        if err != nil || !valid {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("user", claims)
        c.Next()
    }
}

// Use middleware
r.Use(JWTMiddleware())
```

### Basic HTTP Server
```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
    }

    token, err := jwt.CreateToken(secretKey, claims)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{
        "access_token": token,
        "token_type":   "Bearer",
    })
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    
    claims, valid, err := jwt.ValidateToken(secretKey, tokenString)
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
```

## 🛡️ Security Features

This library implements multiple security layers:

### Input Validation
- **Secret Key Requirements**: Minimum 32 bytes with entropy validation
- **Claims Validation**: String length limits, array size limits, control character filtering
- **Pattern Detection**: Blocks suspicious patterns (XSS, SQL injection, path traversal)
- **Size Limits**: Maximum 256 bytes per string field, 100 items per array, 50 extra fields

### Token Security
- **Algorithm Verification**: Strict signing method validation (prevents algorithm confusion attacks)
- **Token Revocation**: Blacklist support with configurable cleanup
- **Expiration Enforcement**: Automatic validation of `exp`, `nbf`, and `iat` claims
- **Issuer Validation**: Optional issuer claim verification

### Operational Security
- **Rate Limiting**: Token bucket algorithm with per-user limits
- **Thread Safety**: All operations are goroutine-safe
- **Secure Cleanup**: Secret keys are zeroed on processor close
- **Resource Limits**: Configurable blacklist size and cache limits

### Standards Compliance
- Follows JWT RFC 7519 specification
- Implements HMAC-SHA256/384/512 signing methods
- Validates registered claims per specification

## 📚 Detailed Documentation

| Documentation                              | Content                       | Use Case                   |
|--------------------------------------------|-------------------------------|----------------------------|
| [API Reference](docs/API.md)               | Complete API documentation    | Development reference      |
| [Security Guide](docs/SECURITY.md)         | Security features explained   | Security audits            |
| [Performance Guide](docs/PERFORMANCE.md)   | Performance optimization tips | High-concurrency scenarios |
| [Integration Examples](docs/EXAMPLES.md)   | Framework integration code    | Project integration        |
| [Best Practices](docs/BEST_PRACTICES.md)   | Production environment guide  | Deployment                 |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common problem solutions      | Issue diagnosis            |

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 🌟 Star History

If you find this project useful, please consider giving it a star! ⭐

---

**Made with ❤️ by the CyberGoDev team**
