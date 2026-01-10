# JWT Library - Security Guide

This document describes the security features and best practices for using the JWT library.

## 🛡️ Security Overview

The JWT library implements multiple security layers including input validation, rate limiting, token revocation, and secure key handling.

### Attack Protection

| Attack Type             | Protection Method                    |
|-------------------------|--------------------------------------|
| **Algorithm Confusion** | Strict algorithm validation          |
| **Timing Attacks**      | Constant-time comparison operations  |
| **Injection Attacks**   | Input validation and sanitization    |
| **DoS Attacks**         | Rate limiting and resource limits    |
| **Replay Attacks**      | Token blacklist with unique IDs      |
| **Brute Force**         | Rate limiting on authentication      |

### Security Testing

Run the security test suite:

```bash
go test -v -run TestSecurity
```

## 🔐 Secret Key Security

### Key Requirements

The library enforces strict secret key requirements:

- **Minimum Length**: 32 bytes (256 bits)
- **Entropy**: Must have sufficient character diversity
- **Pattern Detection**: Rejects common weak patterns

### Weak Key Detection

The following keys will be rejected:

```go
// ❌ Too short
"short"

// ❌ Low entropy
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"abababababababababababababababab"

// ❌ Common patterns
"12345678901234567890123456789012"
"qwertyuiopasdfghjklzxcvbnm123456"
"passwordpasswordpasswordpassword"
```

### Generating Secure Keys

```go
// Use crypto/rand for secure key generation
func generateSecureKey() (string, error) {
    key := make([]byte, 64)
    _, err := rand.Read(key)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(key), nil
}
```

## ⏱️ Timing Attack Protection

### Constant-Time Operations

The library uses constant-time comparison for signature verification to prevent timing attacks:

```go
// Constant-time comparison prevents timing analysis
func SecureCompare(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }

    var result byte
    for i := 0; i < len(a); i++ {
        result |= a[i] ^ b[i]
    }
    return result == 0
}
```

### Uniform Error Responses

All validation errors return the same generic error to prevent information leakage:

```go
var ErrInvalidToken = errors.New("invalid token")
```

This prevents attackers from distinguishing between:
- Invalid signature
- Expired token
- Malformed token
- Wrong algorithm
- Blacklisted token

## 🧠 Advanced Memory Security

### 🔥 5-Pass Secure Memory Wiping (DoD 5220.22-M Standard)

The JWT library implements **Department of Defense level memory wiping** to prevent memory forensics and cold boot attacks:

```go
// ZeroBytes securely zeros a byte slice with multiple passes
func ZeroBytes(data []byte) {
    if len(data) == 0 {
        return
    }

    // Pass 1: Zero all bytes (0x00)
    for i := range data {
        data[i] = 0
    }

    // Pass 2: Fill with cryptographically secure random data
    randomData := make([]byte, len(data))
    rand.Read(randomData)  // crypto/rand for security
    copy(data, randomData)

    // Pass 3: Fill with 0xFF (all bits set)
    for i := range data {
        data[i] = 0xFF
    }

    // Pass 4: Fill with alternating pattern (prevents magnetic recovery)
    for i := range data {
        data[i] = byte(i % 256)
    }

    // Pass 5: Final zero pass (0x00)
    for i := range data {
        data[i] = 0
    }

    // Ensure compiler doesn't optimize away the writes
    runtime.KeepAlive(data)
}
```

### 🔒 SecureBytes: Automatic Memory Protection

```go
// SecureBytes represents a secure byte slice with automatic cleanup
type SecureBytes struct {
    data []byte
    mu   sync.Mutex // Protect against concurrent access during cleanup
}

// NewSecureBytesFromSlice creates a secure byte slice from existing data
func NewSecureBytesFromSlice(data []byte) *SecureBytes {
    secure := &SecureBytes{
        data: make([]byte, len(data)),
    }
    copy(secure.data, data)

    // Set finalizer for automatic cleanup on GC
    // Only for larger allocations to reduce GC pressure
    if len(data) > 256 {
        runtime.SetFinalizer(secure, (*SecureBytes).destroy)
    }

    return secure
}

// Destroy securely zeros the memory and marks for cleanup
func (s *SecureBytes) Destroy() {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.destroy()
    runtime.SetFinalizer(s, nil)
}

// destroy is the internal cleanup function (must be called with mutex held)
func (s *SecureBytes) destroy() {
    if s.data != nil {
        ZeroBytes(s.data)  // 5-pass secure wipe
        s.data = nil
    }
}
```

### 🛡️ Memory Protection in Practice

```go
// Example: Secure key handling throughout the JWT lifecycle
func (p *Processor) createTokenWithClaims(claims Claims) (string, error) {
    // Secret key is stored in SecureBytes
    secretKey := p.secretKey  // *SecureBytes type

    // Get key bytes for signing (protected access)
    keyBytes := secretKey.Bytes()

    // Sign token using HMAC
    token := core.NewTokenWithClaims(signingMethod, claimsCopy)
    tokenString, err := token.SignedString(keyBytes)

    // keyBytes are automatically zeroed when SecureBytes is destroyed
    // No manual cleanup required - handled by finalizer

    return tokenString, nil
}

// Processor cleanup ensures all sensitive data is wiped
func (p *Processor) Close() error {
    if p.secretKey != nil {
        p.secretKey.Destroy()  // 5-pass secure wipe
        p.secretKey = nil
    }
    // ... other cleanup
}
```

### 🔬 Memory Security Validation

```go
// Automated memory protection testing
func TestSecurityMemoryProtection(t *testing.T) {
    processor, err := New(secretKey)
    if err != nil {
        t.Fatalf("Failed to create processor: %v", err)
    }
    defer processor.Close()

    // Create and validate multiple tokens to test memory handling
    for i := 0; i < 100; i++ {
        claims := Claims{
            UserID:   "user" + fmt.Sprintf("%d", i),
            Username: "test" + fmt.Sprintf("%d", i),
        }

        token, err := processor.CreateToken(claims)
        if err != nil {
            t.Fatalf("Failed to create token %d: %v", i, err)
        }

        _, valid, err := processor.ValidateToken(token)
        if err != nil || !valid {
            t.Fatalf("Failed to validate token %d: %v", i, err)
        }
    }

    // Test should complete without memory leaks or issues
    // All sensitive data automatically wiped by SecureBytes finalizers
}
```

## 🚫 DoS Protection

### Input Validation

The library enforces limits to prevent DoS attacks:

```go
const (
    MaxTokenSize     = 8192   // 8KB
    MaxClaimsSize    = 4096   // 4KB
    MaxBlacklistSize = 100000 // 100K entries
)
```

### Rate Limiting

Enable rate limiting to protect against abuse:

```go
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100
config.RateLimitWindow = time.Minute

processor, err := jwt.New(secretKey, config)
```

### Error Handling

```go
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
    return
}
```

## 🔄 Token Revocation & Blacklist

### Token Revocation

Revoke tokens to prevent replay attacks:

```go
// Revoke a token by its ID
err := processor.RevokeToken(tokenString)
if err != nil {
    return fmt.Errorf("failed to revoke token: %w", err)
}
```

### Blacklist Configuration

```go
blacklistConfig := jwt.DefaultBlacklistConfig()
blacklistConfig.MaxSize = 100000
blacklistConfig.CleanupInterval = 5 * time.Minute

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

### Checking Revoked Tokens

Blacklist checking is automatic during validation:

```go
claims, valid, err := processor.ValidateToken(tokenString)
if err == jwt.ErrTokenRevoked {
    http.Error(w, "Token has been revoked", http.StatusUnauthorized)
    return
}
```

## 💉 Input Validation

### Claims Validation

The library validates all claims fields to prevent injection attacks:

```go
// Automatic validation during token creation
claims := jwt.Claims{
    UserID:   "user123",
    Username: "john.doe",
    Role:     "admin",
}

token, err := processor.CreateToken(claims)
if err != nil {
    return fmt.Errorf("validation failed: %w", err)
}
```

### Field Limits

- Maximum field length: 256 characters
- Maximum array size: 100 elements
- Maximum extra claims: 50 entries
- Null bytes and control characters are rejected

## 🔐 Algorithm Validation

### Strict Algorithm Enforcement

The library enforces strict algorithm validation:

- Rejects "none" algorithm tokens
- Only allows HS256, HS384, HS512
- Validates algorithm matches configuration
- Prevents algorithm confusion attacks

```go
config := jwt.DefaultConfig()
config.SigningMethod = jwt.HS256

processor, err := jwt.New(secretKey, config)
```

## 🚀 Performance & Concurrency

### Thread Safety

All public APIs are goroutine-safe:

```go
// Safe for concurrent use
processor, err := jwt.New(secretKey)

// Multiple goroutines can safely validate tokens
go func() {
    claims, valid, _ := processor.ValidateToken(token1)
}()

go func() {
    claims, valid, _ := processor.ValidateToken(token2)
}()
```

### Resource Management

Always close processors to release resources:

```go
processor, err := jwt.New(secretKey)
if err != nil {
    return err
}
defer processor.Close()
```

## 📋 Security Best Practices

### Key Management

```go
// ✅ Use environment variables
secretKey := os.Getenv("JWT_SECRET_KEY")
if secretKey == "" {
    log.Fatal("JWT_SECRET_KEY required")
}

// ❌ Never hardcode secrets
// secretKey := "hardcoded-secret"
```

### Token Expiration

```go
config := jwt.DefaultConfig()
config.AccessTokenTTL = 15 * time.Minute
config.RefreshTokenTTL = 7 * 24 * time.Hour

processor, err := jwt.New(secretKey, config)
```

### Error Handling

```go
claims, valid, err := processor.ValidateToken(token)
if err != nil || !valid {
    http.Error(w, "Invalid token", http.StatusUnauthorized)
    log.Printf("Validation failed: %v", err)
    return
}
```

### Security Checklist

- [ ] Secret key is at least 32 bytes
- [ ] Key stored in environment variables
- [ ] Access token TTL ≤ 15 minutes
- [ ] Rate limiting enabled
- [ ] Blacklist management configured
- [ ] Error handling doesn't leak information
- [ ] Security tests pass: `go test -v -run TestSecurity`

---

## 📚 Security Resources

### Standards & Specifications

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### Security Testing

```bash
go test -v -run TestSecurity
go test -race
go vet ./...
```

---

For security questions or to report vulnerabilities, please follow responsible disclosure practices.
