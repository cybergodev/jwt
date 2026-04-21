# JWT Library - Security Guide

This document describes the security features and best practices for using the JWT library.

## Security Overview

The JWT library implements multiple security layers including input validation, rate limiting, token revocation, and secure key handling.

### Attack Protection

| Attack Type             | Protection Method                    |
|-------------------------|--------------------------------------|
| **Algorithm Confusion** | Strict algorithm validation          |
| **Timing Attacks**      | Constant-time comparison (`hmac.Equal`) |
| **Injection Attacks**   | Input validation and sanitization    |
| **DoS Attacks**         | Rate limiting and resource limits    |
| **Replay Attacks**      | Token blacklist with unique IDs      |
| **Brute Force**         | Rate limiting on authentication      |

### Security Testing

Run the security test suite:

```bash
go test -v -run TestSecurity
```

## Secret Key Security

### Key Requirements

The library enforces strict secret key requirements:

- **Minimum Length**: 32 bytes (256 bits)
- **Entropy**: Must have sufficient character diversity
- **Pattern Detection**: Rejects common weak patterns

### Weak Key Detection

The following keys will be rejected:

```go
// Too short
"short"

// Low entropy
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"abababababababababababababababab"

// Common patterns
"12345678901234567890123456789012"
"qwertyuiopasdfghjklzxcvbnm123456"
"passwordpasswordpasswordpassword"
```

### Generating Secure Keys

```go
// Use crypto/rand for secure key generation
func generateSecureKey() (string, error) {
    key := make([]byte, 64)
    _, err := crypto_rand.Read(key)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(key), nil
}
```

## Timing Attack Protection

### Constant-Time Operations

The library uses `hmac.Equal` for constant-time signature comparison internally. This prevents attackers from measuring response time differences to deduce information about the expected signature.

```go
// Internal implementation (in internal/hmac.go):
// hmac.Equal(sigBytes, expectedSigBytes) is used for all HMAC verification
// This provides constant-time comparison regardless of input
```

### Uniform Error Responses

Signature verification errors all return the same generic message (`"signature verification failed"`) to prevent information leakage about the expected value.

## Memory Security

### Secure Memory Clearing

The library securely clears sensitive data when the processor is closed:

```go
// Internal implementation (in internal/memory.go):
func ZeroBytes(data []byte) {
    clear(data)
    runtime.KeepAlive(data)
}
```

When `Processor.Close()` is called, the secret key bytes are cleared from memory using `ZeroBytes` to minimize the window of exposure.

### Processor Cleanup

```go
processor, err := jwt.New(cfg)
if err != nil {
    return err
}
defer processor.Close() // Clears secret key from memory

// After Close():
// - Secret key bytes are zeroed
// - Blacklist resources are released
// - Rate limiter is shut down
// - Further operations return ErrProcessorClosed
```

## DoS Protection

### Input Validation

The library enforces internal limits to prevent DoS attacks:

| Limit | Value | Description |
|-------|-------|-------------|
| `maxTokenLength` | 8192 | Maximum token size in bytes (internal) |
| `maxSegmentLength` | 4096 | Maximum base64 segment size (internal) |
| `MaxSize` | 100000 | Default maximum blacklist entries |

### Rate Limiting

Enable rate limiting to protect against abuse:

```go
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
cfg.EnableRateLimit = true
cfg.RateLimitRate = 100
cfg.RateLimitWindow = time.Minute

processor, err := jwt.New(cfg)
```

### Error Handling

```go
token, err := processor.Create(&claims)
if err != nil {
    if errors.Is(err, jwt.ErrRateLimitExceeded) {
        http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
        return
    }
    // Handle other errors
}
```

## Token Revocation & Blacklist

### Token Revocation

Revoke tokens to prevent replay attacks:

```go
err := processor.Revoke(tokenString)
if err != nil {
    return fmt.Errorf("failed to revoke token: %w", err)
}
```

### Blacklist Configuration

```go
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
cfg.Blacklist = jwt.BlacklistConfig{
    MaxSize:           100000,
    CleanupInterval:   5 * time.Minute,
    EnableAutoCleanup: true,
}

processor, err := jwt.New(cfg)
```

### Checking Revoked Tokens

Blacklist checking is automatic during validation:

```go
claims, valid, err := processor.Validate(tokenString)
if err != nil {
    if errors.Is(err, jwt.ErrTokenRevoked) {
        http.Error(w, "Token has been revoked", http.StatusUnauthorized)
        return
    }
}
```

## Input Validation

### Claims Validation

The library validates all claims fields to prevent injection attacks:

```go
// Automatic validation during token creation
claims := &jwt.Claims{
    UserID:   "user123",
    Username: "john.doe",
    Role:     "admin",
}

token, err := processor.Create(claims)
if err != nil {
    return fmt.Errorf("validation failed: %w", err)
}
```

### Field Limits

- Maximum field length: 256 characters
- Maximum array size: 100 elements
- Maximum extra claims: 50 entries
- Null bytes and control characters are rejected

## Algorithm Validation

### Strict Algorithm Enforcement

The library enforces strict algorithm validation:

- Rejects "none" algorithm tokens
- Supports HMAC: HS256, HS384, HS512
- Supports RSA: RS256, RS384, RS512
- Supports ECDSA: ES256, ES384, ES512
- Validates algorithm in token header matches configured algorithm
- Prevents algorithm confusion attacks

```go
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
cfg.SigningMethod = jwt.SigningMethodHS256

processor, err := jwt.New(cfg)
```

## Thread Safety

All public APIs are goroutine-safe:

```go
processor, err := jwt.New(cfg)

// Multiple goroutines can safely use the same processor
go func() {
    claims, valid, _ := processor.Validate(token1)
}()

go func() {
    claims, valid, _ := processor.Validate(token2)
}()
```

### Resource Management

Always close processors to release resources:

```go
processor, err := jwt.New(cfg)
if err != nil {
    return err
}
defer processor.Close()
```

## Security Best Practices

### Key Management

```go
// Use environment variables
secretKey := os.Getenv("JWT_SECRET_KEY")
if secretKey == "" {
    log.Fatal("JWT_SECRET_KEY required")
}

// Never hardcode secrets
// secretKey := "hardcoded-secret" // BAD
```

### Token Expiration

```go
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
cfg.AccessTokenTTL = 15 * time.Minute
cfg.RefreshTokenTTL = 7 * 24 * time.Hour

processor, err := jwt.New(cfg)
```

### Error Handling

```go
claims, valid, err := processor.Validate(token)
if err != nil || !valid {
    http.Error(w, "Invalid token", http.StatusUnauthorized)
    // Avoid logging the actual token value
    return
}
```

### Security Checklist

- [ ] Secret key is at least 32 bytes
- [ ] Key stored in environment variables
- [ ] Access token TTL is short (15 minutes recommended)
- [ ] Rate limiting enabled in production
- [ ] Blacklist management configured
- [ ] Error handling doesn't leak information
- [ ] Security tests pass: `go test -v -run TestSecurity`

## Security Resources

### Standards & Specifications

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### Security Testing

```bash
go test -v -run TestSecurity
go test -race ./...
go vet ./...
```

---

For security questions or to report vulnerabilities, please follow responsible disclosure practices.
