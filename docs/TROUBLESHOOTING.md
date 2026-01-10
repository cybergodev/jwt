# JWT Library - Troubleshooting Guide

This guide helps diagnose and resolve common issues.

## 🚨 Quick Fixes

| Issue | Solution |
|-------|----------|
| "invalid secret key" | Check key length ≥32 bytes |
| "token validation failed" | Verify token format (3 parts) |
| "rate limit exceeded" | Adjust rate limit configuration |
| High memory usage | Call processor.Close() |

## 🔥 Common Issues

### Invalid Secret Key

**Problem:** `invalid secret key` error

**Causes:**
- Key too short (<32 bytes)
- Empty environment variable
- Weak key patterns

**Solution:**
```go
// Generate secure key
keyBytes := make([]byte, 64)
rand.Read(keyBytes)
secretKey := base64.URLEncoding.EncodeToString(keyBytes)

// Or use environment variable
secretKey := os.Getenv("JWT_SECRET_KEY")
if secretKey == "" {
    log.Fatal("JWT_SECRET_KEY required")
}

processor, err := jwt.New(secretKey)
if err != nil {
    log.Fatalf("Invalid key: %v", err)
}
```

### Token Validation Failed

**Problem:** `invalid token` error

**Causes:**
- Token expired
- Wrong secret key
- Malformed token format
- Token revoked

**Solution:**
```go
// Check token format (should have 3 parts)
parts := strings.Split(token, ".")
if len(parts) != 3 {
    log.Println("Invalid token format")
}

// Validate with correct key
claims, valid, err := processor.ValidateToken(token)
if err != nil {
    log.Printf("Validation error: %v", err)
}

if !valid {
    log.Println("Token invalid or expired")
}

// Check if revoked
if processor.IsRevoked(tokenID) {
    log.Println("Token was revoked")
}
```

### Rate Limit Exceeded

**Problem:** `rate limit exceeded` error

**Causes:**
- Too many requests
- Rate limit too low
- Rate limit not configured

**Solution:**
```go
// Adjust rate limits
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 200  // Increase limit
config.RateLimitWindow = time.Minute

processor, err := jwt.New(secretKey, config)
```

### High Memory Usage

**Problem:** Memory continuously increasing

**Causes:**
- Processor not closed
- Too many processors created
- Blacklist too large

**Solution:**
```go
// Always close processor
processor, err := jwt.New(secretKey)
if err != nil {
    return err
}
defer processor.Close()

// Graceful shutdown
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

go func() {
    <-sigChan
    processor.Close()
    os.Exit(0)
}()

// Configure blacklist size
blacklistConfig := jwt.DefaultBlacklistConfig()
blacklistConfig.MaxSize = 50000  // Adjust as needed
blacklistConfig.CleanupInterval = 5 * time.Minute

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

### Token Not Revoked

**Problem:** Revoked token still validates

**Causes:**
- Blacklist not enabled
- Wrong token ID used
- Blacklist size exceeded

**Solution:**
```go
// Enable blacklist
blacklistConfig := jwt.DefaultBlacklistConfig()
processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig)

// Revoke by token ID
err := processor.RevokeToken(tokenID)
if err != nil {
    log.Printf("Revocation failed: %v", err)
}

// Check if revoked
if processor.IsRevoked(tokenID) {
    log.Println("Token is revoked")
}
```

### Concurrent Access Issues

**Problem:** Race conditions or panics

**Causes:**
- Multiple goroutines using same processor
- Not thread-safe usage

**Solution:**
```go
// Processor is thread-safe
processor, err := jwt.New(secretKey)
defer processor.Close()

// Safe to use from multiple goroutines
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(token string) {
        defer wg.Done()
        claims, valid, _ := processor.ValidateToken(token)
        // Process claims...
    }(tokens[i])
}
wg.Wait()
```

## 📊 Debugging

### Enable Logging

```go
// Add logging to track operations
log.Printf("Creating token for user %s", userID)
token, err := processor.CreateToken(claims)
if err != nil {
    log.Printf("Token creation failed: %v", err)
}

log.Printf("Validating token")
claims, valid, err := processor.ValidateToken(token)
if err != nil {
    log.Printf("Validation error: %v", err)
}
```

### Memory Profiling

```bash
# Profile memory usage
go test -bench=. -memprofile=mem.prof
go tool pprof mem.prof

# Check for leaks
go test -run TestMemory -v
```

### Performance Testing

```bash
# Run benchmarks
go test -bench=. -benchmem

# Stress test
go test -bench=BenchmarkConcurrent -benchtime=60s
```

## 🎯 Checklist

Before deploying:
- [ ] Secret key ≥32 bytes
- [ ] Processor.Close() called
- [ ] Error handling implemented
- [ ] Rate limits configured
- [ ] Logging enabled
- [ ] Tests passing

---

For more details, see [API.md](API.md) and [BEST_PRACTICES.md](BEST_PRACTICES.md).
