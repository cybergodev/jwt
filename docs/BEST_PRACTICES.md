# JWT Library - Best Practices

This guide provides practical best practices for production deployments.

## 🎯 Production Checklist

- [ ] Secret key ≥32 bytes, stored in environment variables
- [ ] Access token TTL ≤15 minutes
- [ ] Rate limiting configured
- [ ] Token revocation enabled
- [ ] Processor.Close() called on shutdown
- [ ] Error handling implemented
- [ ] Monitoring in place

## 🔐 Key Management

### Generate Secure Keys

```go
func generateSecureKey() (string, error) {
    keyBytes := make([]byte, 64)
    if _, err := rand.Read(keyBytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(keyBytes), nil
}
```

### Store Keys Securely

```go
// ✅ Use environment variables
secretKey := os.Getenv("JWT_SECRET_KEY")
if secretKey == "" {
    log.Fatal("JWT_SECRET_KEY required")
}

processor, err := jwt.New(secretKey)
if err != nil {
    log.Fatalf("Invalid key: %v", err)
}
defer processor.Close()
```

### Key Rotation

For key rotation, maintain both current and previous keys during a grace period:

```go
// Validate with current key first
claims, valid, err := currentProcessor.ValidateToken(token)
if err != nil && previousProcessor != nil {
    // Try previous key during grace period
    claims, valid, err = previousProcessor.ValidateToken(token)
}
```

## ⚙️ Configuration

### Token TTL

```go
config := jwt.DefaultConfig()
config.AccessTokenTTL = 15 * time.Minute
config.RefreshTokenTTL = 24 * time.Hour

processor, err := jwt.New(secretKey, config)
```

### Rate Limiting

```go
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100
config.RateLimitWindow = time.Minute

processor, err := jwt.New(secretKey, config)
```

### Token Revocation

```go
blacklistConfig := jwt.DefaultBlacklistConfig()
blacklistConfig.MaxSize = 100000
blacklistConfig.CleanupInterval = 5 * time.Minute

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

## 🔍 Error Handling

### Validate Tokens

```go
claims, valid, err := processor.ValidateToken(token)
if err != nil {
    log.Printf("Validation error: %v", err)
    return http.StatusUnauthorized
}

if !valid {
    log.Printf("Invalid token")
    return http.StatusUnauthorized
}

// Use claims
userID := claims.Subject
```

### Handle Revocation

```go
// Revoke token
if err := processor.RevokeToken(tokenID); err != nil {
    log.Printf("Revocation failed: %v", err)
    return err
}

// Check if revoked
if processor.IsRevoked(tokenID) {
    return http.StatusUnauthorized
}
```

## 🔧 Resource Management

### Cleanup

```go
processor, err := jwt.New(secretKey)
if err != nil {
    return err
}
defer processor.Close() // Always close

// Use processor
```

### Graceful Shutdown

```go
func main() {
    processor, err := jwt.New(secretKey)
    if err != nil {
        log.Fatal(err)
    }

    // Handle shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-sigChan
        log.Println("Shutting down...")
        processor.Close()
        os.Exit(0)
    }()

    // Run application
}
```

## 📊 Monitoring

### Log Important Events

```go
// Token creation
log.Printf("Token created for user %s", userID)

// Validation failures
log.Printf("Token validation failed: %v", err)

// Revocations
log.Printf("Token %s revoked", tokenID)

// Rate limit hits
log.Printf("Rate limit exceeded for user %s", userID)
```

### Track Metrics

Monitor these metrics in production:
- Token creation rate
- Validation success/failure rate
- Revocation rate
- Rate limit hits
- Average validation latency

---

For more details, see [API.md](API.md), [SECURITY.md](SECURITY.md), and [PERFORMANCE.md](PERFORMANCE.md).