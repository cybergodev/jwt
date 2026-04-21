# JWT Library - Concurrency Guide

This guide covers thread safety, concurrent patterns, and best practices for using the JWT library in concurrent applications.

## Table of Contents

- [Thread Safety Guarantees](#thread-safety-guarantees)
- [Concurrent Patterns](#concurrent-patterns)
- [Synchronization](#synchronization)
- [Memory Model](#memory-model)
- [Common Pitfalls](#common-pitfalls)
- [Testing Concurrent Code](#testing-concurrent-code)

---

## Thread Safety Guarantees

### Processor is Thread-Safe

All public methods of `Processor` are safe for concurrent use:

```go
// SAFE: Multiple goroutines can use the same processor
processor, _ := jwt.New(cfg)
defer processor.Close()

// Goroutine 1
go func() {
    token, _ := processor.Create(claims1)
}()

// Goroutine 2
go func() {
    claims, _, _ := processor.Validate(token2)
}()

// Goroutine 3
go func() {
    processor.Revoke(token3)
}()
```

### Thread-Safe Components

| Component | Thread-Safe | Notes |
|-----------|-------------|-------|
| `Processor` | ✅ Yes | All methods are concurrent-safe |
| `Claims` | ⚠️ Caution | Safe for read, not for concurrent writes |
| `Config` | ❌ No | Configure before creating Processor |
| `BlacklistStore` | ✅ Yes | Built-in implementations are thread-safe |
| `RateLimiter` | ✅ Yes | Built-in implementation is thread-safe |

### What's Protected Internally

```go
type Processor struct {
    // These fields are protected by atomic operations or mutexes:
    closed           atomic.Bool      // Atomic flag
    blacklistManager *Manager         // Has internal synchronization (sync.RWMutex)
    rateLimiter      RateLimitProvider // Interface requires thread-safety

    // These are read-only after creation:
    secretKey        []byte         // Immutable after New() (zeroed on Close)
    asymmetricKey    any            // Immutable after New() (nil'd on Close)
    verificationKey  any            // Immutable after New() (nil'd on Close)
    signingMethod    SigningMethod  // Immutable after New()
    accessTokenTTL   time.Duration  // Immutable after New()
    refreshTokenTTL  time.Duration  // Immutable after New()
    issuer           string         // Immutable after New()
    audience         string         // Immutable after New()
    clock            ClockProvider  // Immutable after New()
}
```

---

## Concurrent Patterns

### Pattern 1: Shared Processor

The most common pattern - share a single processor across all goroutines:

```go
// Global processor (or dependency-injected)
var processor *jwt.Processor

func init() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = os.Getenv("JWT_SECRET")
    processor, _ = jwt.New(cfg)
}

func handler(w http.ResponseWriter, r *http.Request) {
    // Each request uses the same processor concurrently
    token := r.Header.Get("Authorization")
    claims, valid, err := processor.Validate(token)
    // ...
}
```

### Pattern 2: Worker Pool

For batch processing with worker pools:

```go
func processTokens(processor *jwt.Processor, tokens <-chan string, results chan<- Result) {
    for token := range tokens {
        claims, valid, err := processor.Validate(token)
        results <- Result{
            Token:  token,
            Claims: claims,
            Valid:  valid,
            Error:  err,
        }
    }
}

func main() {
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    tokens := make(chan string, 100)
    results := make(chan Result, 100)

    // Start workers
    for i := 0; i < 10; i++ {
        go processTokens(processor, tokens, results)
    }

    // Send tokens
    for _, token := range tokenList {
        tokens <- token
    }
    close(tokens)

    // Collect results
    for i := 0; i < len(tokenList); i++ {
        result := <-results
        // Process result
    }
}
```

### Pattern 3: Per-Request Context

Pass processor through request context:

```go
func middleware(processor *jwt.Processor) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := r.Header.Get("Authorization")
            claims, valid, err := processor.Validate(token)

            if !valid || err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Add claims to context
            ctx := context.WithValue(r.Context(), "claims", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func handler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value("claims").(jwt.Claims)
    // Use claims...
}
```

### Pattern 4: Token Refresh Pipeline

Concurrent token refresh with rate limiting:

```go
type TokenRefresher struct {
    processor *jwt.Processor
    mu        sync.RWMutex
    cache     map[string]cachedToken
}

type cachedToken struct {
    accessToken string
    expiresAt   time.Time
}

func (r *TokenRefresher) GetToken(userID string) (string, error) {
    // Check cache first (read lock)
    r.mu.RLock()
    if cached, ok := r.cache[userID]; ok {
        if time.Now().Before(cached.expiresAt.Add(-time.Minute)) {
            r.mu.RUnlock()
            return cached.accessToken, nil
        }
    }
    r.mu.RUnlock()

    // Create new token (write lock)
    r.mu.Lock()
    defer r.mu.Unlock()

    // Double-check after acquiring write lock
    if cached, ok := r.cache[userID]; ok {
        if time.Now().Before(cached.expiresAt.Add(-time.Minute)) {
            return cached.accessToken, nil
        }
    }

    claims := &jwt.Claims{UserID: userID}
    token, err := r.processor.Create(claims)
    if err != nil {
        return "", err
    }

    r.cache[userID] = cachedToken{
        accessToken: token,
        expiresAt:   time.Now().Add(15 * time.Minute),
    }

    return token, nil
}
```

---

## Synchronization

### Internal Synchronization

The library uses these synchronization primitives:

1. **sync.Pool**: Object pooling for buffers and structs
2. **sync.RWMutex**: Blacklist store operations (built-in MemoryStore)
3. **atomic.Bool**: Processor closed state

### Claims Synchronization

Claims objects are NOT thread-safe for writes:

```go
// BAD: Concurrent writes to Claims
claims := &jwt.Claims{UserID: "user123"}

go func() {
    claims.Role = "admin" // Race condition!
}()

go func() {
    claims.Role = "user" // Race condition!
}()

// GOOD: Each goroutine has its own Claims
go func() {
    claims1 := &jwt.Claims{UserID: "user123", Role: "admin"}
    token1, _ := processor.Create(claims1)
}()

go func() {
    claims2 := &jwt.Claims{UserID: "user456", Role: "user"}
    token2, _ := processor.Create(claims2)
}()
```

### Blacklist Thread Safety

The blacklist is fully thread-safe:

```go
// SAFE: Concurrent blacklist operations
go func() {
    processor.Revoke(token1) // Safe
}()

go func() {
    processor.IsRevoked(token2) // Safe
}()

go func() {
    processor.Validate(token3) // Safe (checks blacklist internally)
}()
```

---

## Memory Model

### Happens-Before Guarantees

1. **Processor creation happens-before any operation**

```go
processor, _ := jwt.New(cfg)
// All goroutines see fully initialized processor
go processor.Create(claims)
```

2. **Close() sets atomic flag preventing new operations**

```go
go processor.Create(claims)
processor.Close() // Sets closed flag, releases resources
// After Close() returns, new operations return ErrProcessorClosed
// In-flight operations may still complete
```

3. **Blacklist operations are sequentially consistent**

```go
processor.Revoke(token)
revoked, _ := processor.IsRevoked(token)
// revoked is always true (no stale reads)
```

### Atomic Operations

```go
// Close check uses atomic operation
func (p *Processor) Create(claims CustomClaims) (string, error) {
    if p.closed.Load() { // Atomic read
        return "", ErrProcessorClosed
    }
    // ...
}
```

---

## Common Pitfalls

### Pitfall 1: Modifying Claims After Creation

```go
// BAD
claims := &jwt.Claims{UserID: "user123"}
token, _ := processor.Create(claims)
claims.UserID = "user456" // Doesn't affect the token

// Token still has UserID: "user123"
```

### Pitfall 2: Sharing Claims Across Goroutines

```go
// BAD
claims := &jwt.Claims{UserID: "user123"}

for i := 0; i < 10; i++ {
    go func(idx int) {
        claims.Extra = map[string]any{"index": idx} // Race!
        processor.Create(claims)
    }(i)
}

// GOOD
for i := 0; i < 10; i++ {
    go func(idx int) {
        claims := &jwt.Claims{
            UserID: "user123",
            Extra:  map[string]any{"index": idx},
        }
        processor.Create(claims)
    }(i)
}
```

### Pitfall 3: Using Closed Processor

```go
// BAD
processor, _ := jwt.New(cfg)
processor.Close()

token, err := processor.Create(claims)
// err == ErrProcessorClosed

// GOOD
processor, _ := jwt.New(cfg)
defer processor.Close()

// Check before use
if processor.IsClosed() {
    return errors.New("processor unavailable")
}
```

### Pitfall 4: Not Closing Processor

```go
// BAD: Memory leak, secret key not cleared
func handler(w http.ResponseWriter, r *http.Request) {
    processor, _ := jwt.New(cfg)
    // Missing: defer processor.Close()
    // Secret key remains in memory
}

// GOOD
func main() {
    processor, _ := jwt.New(cfg)
    defer processor.Close() // Always close
}
```

---

## Testing Concurrent Code

### Race Detector

Always test with the race detector:

```bash
go test -race ./...
```

### Concurrent Test Pattern

```go
func TestConcurrentTokenOperations(t *testing.T) {
    processor, err := jwt.New(jwt.DefaultConfig())
    require.NoError(t, err)
    defer processor.Close()

    const goroutines = 100
    const operations = 100

    var wg sync.WaitGroup
    errs := make(chan error, goroutines*operations)

    for i := 0; i < goroutines; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            for j := 0; j < operations; j++ {
                claims := &jwt.Claims{
                    UserID: fmt.Sprintf("user-%d-%d", id, j),
                }

                token, err := processor.Create(claims)
                if err != nil {
                    errs <- err
                    return
                }

                _, valid, err := processor.Validate(token)
                if err != nil || !valid {
                    errs <- fmt.Errorf("validation failed")
                    return
                }
            }
        }(i)
    }

    wg.Wait()
    close(errs)

    for err := range errs {
        t.Errorf("concurrent operation failed: %v", err)
    }
}
```

### Benchmarking Concurrency

```go
func BenchmarkConcurrentValidation(b *testing.B) {
    processor, _ := jwt.New(jwt.DefaultConfig())
    defer processor.Close()

    claims := &jwt.Claims{UserID: "user123"}
    token, _ := processor.Create(claims)

    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, _, _ = processor.Validate(token)
        }
    })
}
```

### Stress Testing

```go
func TestStressTokenRevocation(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping stress test")
    }

    processor, _ := jwt.New(jwt.DefaultConfig())
    defer processor.Close()

    var wg sync.WaitGroup

    // Revoke goroutines
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := 0; j < 1000; j++ {
                claims := &jwt.Claims{UserID: fmt.Sprintf("user-%d", j)}
                token, _ := processor.Create(claims)
                processor.Revoke(token)
            }
        }()
    }

    // Validate goroutines
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := 0; j < 1000; j++ {
                claims := &jwt.Claims{UserID: fmt.Sprintf("user-%d", j)}
                token, _ := processor.Create(claims)
                processor.Validate(token)
            }
        }()
    }

    wg.Wait()
}
```

---

## Concurrency Checklist

- [ ] Processor created once at startup
- [ ] Processor closed on shutdown
- [ ] Each goroutine creates its own Claims
- [ ] Tests run with `-race` flag
- [ ] No concurrent writes to shared Claims
- [ ] Proper error handling for closed processor
- [ ] Stress tests for critical paths
- [ ] Benchmark parallel operations

---
