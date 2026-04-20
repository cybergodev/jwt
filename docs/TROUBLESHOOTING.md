# JWT Library - Troubleshooting Guide

Common issues, solutions, and debugging techniques for the JWT library.

## Table of Contents

- [Common Errors](#common-errors)
- [Configuration Issues](#configuration-issues)
- [Token Issues](#token-issues)
- [Performance Issues](#performance-issues)
- [Security Issues](#security-issues)
- [Debugging Techniques](#debugging-techniques)
- [FAQ](#faq)

---

## Common Errors

### ErrInvalidSecretKey

**Symptoms:**
```
invalid secret key: minimum 32 bytes required, got 16
```

**Cause:** Secret key is too short or has insufficient entropy.

**Solution:**
```go
// ❌ Too short
cfg.SecretKey = "short-key"

// ✅ At least 32 bytes with good entropy
cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+"

// ✅ Generate programmatically
func generateKey() string {
    key := make([]byte, 32)
    rand.Read(key)
    return base64.StdEncoding.EncodeToString(key)
}
```

### ErrTokenExpired

**Symptoms:**
```
token expired
```

**Cause:** Token's `exp` claim is in the past.

**Solution:**
```go
claims, valid, err := processor.Validate(token)
if errors.Is(err, jwt.ErrTokenExpired) {
    // Option 1: Prompt user to refresh
    return &RefreshRequiredError{}

    // Option 2: Use refresh token to get new access token
    newToken, err := processor.Refresh(refreshToken)
}

// Prevent expiration by setting appropriate TTL
cfg.AccessTokenTTL = 15 * time.Minute
```

### ErrTokenRevoked

**Symptoms:**
```
token revoked
```

**Cause:** Token exists in the blacklist.

**Solutions:**

1. **Expected behavior** - User logged out, token was revoked
2. **Blacklist cleanup issue** - Blacklist not cleaning expired tokens

```go
// Check blacklist configuration
cfg.Blacklist = jwt.BlacklistConfig{
    EnableAutoCleanup: true,
    CleanupInterval:   5 * time.Minute,
    MaxSize:           10000,
}
```

### ErrTokenNotValidYet

**Symptoms:**
```
token not valid yet
```

**Cause:** Token's `nbf` (not before) claim is in the future.

**Common causes:**
1. Clock skew between servers
2. Token created with future `nbf`

**Solution:**
```go
// Add clock skew tolerance
// Note: This should be minimal (seconds, not minutes)
// If needed, implement custom validation

// Check server time synchronization
// Ensure NTP is configured on all servers
```

### ErrProcessorClosed

**Symptoms:**
```
processor closed
```

**Cause:** Attempting to use processor after `Close()` was called.

**Solution:**
```go
// Check before using
if processor.IsClosed() {
    return errors.New("service unavailable")
}

// Or handle gracefully
claims, valid, err := processor.Validate(token)
if errors.Is(err, jwt.ErrProcessorClosed) {
    // Return service unavailable
    return &ServiceUnavailableError{}
}
```

---

## Configuration Issues

### Issue: Config validation fails with no clear error

**Symptoms:**
```
invalid configuration
```

**Debug:**
```go
cfg := jwt.DefaultConfig()
cfg.SecretKey = os.Getenv("JWT_SECRET")

if err := cfg.Validate(); err != nil {
    var validationErr *jwt.ValidationError
    if errors.As(err, &validationErr) {
        log.Printf("Field: %s, Message: %s", validationErr.Field, validationErr.Message)
    }
}
```

**Common causes:**
1. Empty `SecretKey`
2. `AccessTokenTTL >= RefreshTokenTTL`
3. Invalid `SigningMethod`
4. Missing `SigningKey` for asymmetric methods

### Issue: Asymmetric key validation fails

**Symptoms:**
```
invalid secret key: RSA method requires *rsa.PrivateKey
```

**Solution:**
```go
// Ensure proper key type
block, _ := pem.Decode(keyData)
if block == nil {
    log.Fatal("failed to decode PEM block")
}

privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
if err != nil {
    log.Fatal(err)
}
rsaKey, ok := privateKey.(*rsa.PrivateKey)
if !ok {
    log.Fatal("not an RSA private key")
}

cfg := jwt.DefaultConfig()
cfg.SigningKey = rsaKey  // Must be *rsa.PrivateKey, not []byte or string
cfg.SigningMethod = jwt.SigningMethodRS256
```

### Issue: Blacklist configuration ignored

**Symptoms:** Blacklist settings not taking effect.

**Cause:** Not passing config properly.

**Solution:**
```go
// ❌ Wrong - creating new blacklist config
cfg := jwt.Config{SecretKey: key}

// ✅ Correct - using DefaultConfig or setting Blacklist
cfg := jwt.DefaultConfig()
cfg.SecretKey = key
cfg.Blacklist = jwt.BlacklistConfig{
    MaxSize:         50000,
    CleanupInterval: 10 * time.Minute,
}
```

---

## Token Issues

### Issue: Token works on one server but not another

**Symptoms:** Token validates on server A but fails on server B.

**Causes:**

1. **Different secret keys**
```bash
# Check environment variables
echo $JWT_SECRET_KEY
```

2. **Clock skew**
```bash
# Check server time
date
# Ensure NTP is synchronized
timedatectl status
```

3. **Different configuration**
```go
// Log configuration on startup
log.Printf("Config: %+v", cfg)
```

### Issue: Token claims are empty after validation

**Symptoms:** Token validates but claims fields are empty.

**Cause:** Claims type mismatch.

**Solution:**
```go
// If using custom claims, use ValidateInto with jwt.RegisteredClaims embedding
type MyClaims struct {
    UserID string `json:"user_id"`
    TeamID string `json:"team_id"`
    jwt.RegisteredClaims
}

func (c *MyClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
    return &c.RegisteredClaims
}

func (c *MyClaims) Validate() error {
    if c.UserID == "" {
        return errors.New("user_id is required")
    }
    return nil
}

claims := &MyClaims{}
result, valid, err := processor.ValidateInto(token, claims)
if valid {
    myClaims := result.(*MyClaims)
    fmt.Println(myClaims.TeamID) // Now accessible
}
```

### Issue: Token too large

**Symptoms:** Token exceeds size limit.

**Cause:** Too many claims or large claim values.

**Solution:**
```go
// Minimize claims
claims := &jwt.Claims{
    UserID: "user123", // Essential only
    Role:   "admin",
}

// Avoid large Extra map
// ❌ Bad
claims.Extra = map[string]any{
    "permissions": make([]string, 100),
    "metadata":    largeObject,
}

// ✅ Good - keep Extra minimal
claims.Extra = map[string]any{
    "org_id": "org-123",
}
```

---

## Performance Issues

### Issue: High memory usage

**Symptoms:** Memory keeps growing.

**Causes:**

1. **Blacklist growing without cleanup**
```go
// Enable auto cleanup
cfg.Blacklist.EnableAutoCleanup = true
cfg.Blacklist.CleanupInterval = 5 * time.Minute
```

2. **Creating processor per request**
```go
// ❌ Bad - creates new processor each time
func handler(w http.ResponseWriter, r *http.Request) {
    processor, _ := jwt.New(cfg)
    defer processor.Close()
}

// ✅ Good - reuse processor
var processor *jwt.Processor
func init() {
    processor, _ = jwt.New(cfg)
}
```

### Issue: Slow token validation

**Symptoms:** Token validation takes too long.

**Debug:**
```go
start := time.Now()
claims, valid, err := processor.Validate(token)
log.Printf("Validation took: %v", time.Since(start))
```

**Causes:**

1. **Rate limiting overhead** - Disable if not needed
2. **Blacklist check** - Large blacklist
3. **RSA/ECDSA algorithms** - Switch to HMAC if possible

**Solution:**
```go
// Profile the operation
func BenchmarkValidation(b *testing.B) {
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    token, _ := processor.Create(claims)
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        processor.Validate(token)
    }
}
```

### Issue: High GC pressure

**Symptoms:** Frequent garbage collection pauses.

**Causes:**
1. Creating many Claims objects
2. Large blacklist

**Solution:**
```go
// Reuse processor (it has internal pooling)
// Limit blacklist size
cfg.Blacklist.MaxSize = 10000

// Profile memory
go test -memprofile=mem.out -bench=.
go tool pprof mem.out
```

---

## Security Issues

### Issue: Weak key warning

**Symptoms:**
```
invalid secret key: key must have sufficient entropy and complexity
```

**Cause:** Key has low entropy (repeated characters, patterns).

**Solution:**
```go
// ❌ Rejected keys
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  // Low entropy
"12345678901234567890123456789012"  // Pattern
"qwertyuiopasdfghjklzxcvbnm123456"  // Keyboard pattern

// ✅ Good keys
"Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~"

// Generate secure key
func generateSecureKey() string {
    key := make([]byte, 32)
    crypto_rand.Read(key)
    return base64.StdEncoding.EncodeToString(key)
}
```

### Issue: Algorithm confusion attack

**Symptoms:** Token with wrong algorithm accepted.

**Cause:** Not explicitly setting expected algorithm.

**Solution:**
```go
// Always set expected algorithm
cfg.SigningMethod = jwt.SigningMethodHS256

// Library validates algorithm in header matches config
// If token has different algorithm, validation fails
```

---

## Debugging Techniques

### Enable Debug Logging

```go
// Wrap processor with logging
type LoggingProcessor struct {
    *jwt.Processor
    logger *slog.Logger
}

func (p *LoggingProcessor) Validate(token string) (jwt.Claims, bool, error) {
    p.logger.Debug("validating token", "token_preview", token[:20]+"...")

    claims, valid, err := p.Processor.Validate(token)

    p.logger.Debug("validation result",
        "valid", valid,
        "user_id", claims.UserID,
        "error", err,
    )

    return claims, valid, err
}
```

### Inspect Token Claims

```go
// Parse without validation (for debugging only)
func inspectToken(tokenString string) {
    parts := strings.Split(tokenString, ".")
    if len(parts) != 3 {
        fmt.Println("Invalid token format")
        return
    }

    // Decode header
    headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
    fmt.Printf("Header: %s\n", headerJSON)

    // Decode claims
    claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
    fmt.Printf("Claims: %s\n", claimsJSON)

    // Signature (base64)
    fmt.Printf("Signature: %s\n", parts[2])
}
```

### Test Configuration

```go
func TestConfig(t *testing.T) {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = os.Getenv("JWT_SECRET_KEY")

    // Validate config
    if err := cfg.Validate(); err != nil {
        t.Fatalf("Config validation failed: %v", err)
    }

    // Create processor
    processor, err := jwt.New(cfg)
    if err != nil {
        t.Fatalf("Failed to create processor: %v", err)
    }
    defer processor.Close()

    // Test round-trip
    claims := &jwt.Claims{UserID: "test"}
    token, err := processor.Create(claims)
    if err != nil {
        t.Fatalf("Failed to create token: %v", err)
    }

    _, valid, err := processor.Validate(token)
    if err != nil || !valid {
        t.Fatalf("Token validation failed: valid=%v, err=%v", valid, err)
    }
}
```

---

## FAQ

### Q: How do I implement "remember me" functionality?

```go
func createSession(userID string, rememberMe bool) (*Session, error) {
    cfg := jwt.DefaultConfig()

    if rememberMe {
        cfg.RefreshTokenTTL = 30 * 24 * time.Hour // 30 days
    } else {
        cfg.RefreshTokenTTL = 24 * time.Hour // 1 day
    }

    processor, _ := jwt.New(cfg)
    // ...
}
```

### Q: How do I invalidate all tokens for a user?

```go
// Option 1: Use token version in claims
type Claims struct {
    jwt.Claims
    TokenVersion int `json:"token_version"`
}

// Store version in database
// When validating, check version matches database
// Increment version to invalidate all tokens

// Option 2: Track all tokens in blacklist
// (Not recommended for large-scale applications)
```

### Q: How do I handle token refresh in mobile apps?

```go
// Mobile apps typically use longer-lived refresh tokens
cfg := jwt.DefaultConfig()
cfg.AccessTokenTTL = 15 * time.Minute
cfg.RefreshTokenTTL = 30 * 24 * time.Hour // 30 days

// On app launch, try to refresh access token
// If refresh fails, prompt for re-login
```

### Q: How do I implement multi-tenant JWT?

```go
type TenantClaims struct {
    jwt.Claims
    TenantID string `json:"tenant_id"`
}

// Validate tenant access
func validateTenantAccess(claims *TenantClaims, requestedTenant string) bool {
    return claims.TenantID == requestedTenant
}
```

### Q: Can I use custom error messages?

```go
// Wrap errors with context
func wrapError(err error) error {
    switch {
    case errors.Is(err, jwt.ErrTokenExpired):
        return errors.New("your session has expired, please log in again")
    case errors.Is(err, jwt.ErrTokenRevoked):
        return errors.New("this session has been terminated")
    default:
        return errors.New("authentication failed")
    }
}
```

---

## Getting Help

1. **Check documentation**: [API Reference](API.md), [Best Practices](BEST_PRACTICES.md)
2. **Search issues**: [GitHub Issues](https://github.com/cybergodev/jwt/issues)
3. **Enable debug logging**: See [Debugging Techniques](#debugging-techniques)
4. **Report bugs**: Include Go version, library version, and minimal reproduction

---
