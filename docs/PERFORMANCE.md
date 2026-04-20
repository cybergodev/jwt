# JWT Library - Performance Guide

This guide covers performance characteristics, optimization techniques, and benchmarking for high-throughput JWT operations.

## Table of Contents

- [Performance Characteristics](#performance-characteristics)
- [Benchmarks](#benchmarks)
- [Memory Management](#memory-management)
- [Optimization Techniques](#optimization-techniques)
- [Profiling](#profiling)
- [Best Practices](#best-practices)

---

## Performance Characteristics

### Benchmark Results (Go 1.25, Intel Ultra 9 185H)

| Operation | Time | Memory | Allocations |
|-----------|------|--------|-------------|
| Token Creation | ~4.6µs | ~1.8KB | 19 allocs |
| Token Validation | ~5.0µs | ~2.3KB | 41 allocs |
| Create + Validate | ~9.8µs | ~3.6KB | 56 allocs |
| Concurrent Creation | ~1.2µs | ~1.8KB | 19 allocs |
| Concurrent Validation | ~1.0µs | ~2.4KB | 43 allocs |
| Blacklist Operations | ~2.9µs | ~1.4KB | 21 allocs |

### Throughput

| Scenario | Operations/sec |
|----------|----------------|
| Single-threaded token creation | ~210,000 |
| Single-threaded validation | ~200,000 |
| Concurrent operations (22 cores) | ~800,000+ |

### Algorithm Comparison

| Algorithm | Create + Validate | Notes |
|-----------|-------------------|-------|
| HS256 | ~10µs | Fastest, recommended for HMAC |
| HS384 | ~12µs | More secure, slightly slower |
| HS512 | ~12µs | Most secure HMAC option |
| RS256 | ~15ms | Asymmetric, slower due to RSA |
| ES256 | ~8ms | Asymmetric, faster than RSA |

---

## Benchmarks

### Running Benchmarks

```bash
# Run all benchmarks
go test -bench=. -benchmem ./...

# Run specific benchmarks
go test -bench=BenchmarkTokenCreation -benchmem ./...

# Run with CPU profiling
go test -bench=. -cpuprofile=cpu.out ./...
go tool pprof cpu.out

# Run with memory profiling
go test -bench=. -memprofile=mem.out ./...
go tool pprof mem.out

# Race detection + benchmarks
go test -race -bench=. -benchmem ./...
```

### Available Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkTokenCreation` | Token creation performance |
| `BenchmarkTokenValidation` | Token validation performance |
| `BenchmarkTokenCreationAndValidation` | Combined operation |
| `BenchmarkBlacklistOperations` | Token revocation |
| `BenchmarkBlacklistValidation` | Validation with blacklist check |
| `BenchmarkConcurrentTokenCreation` | Parallel token creation |
| `BenchmarkConcurrentTokenValidation` | Parallel validation |
| `BenchmarkDifferentSigningMethods` | Algorithm comparison |
| `BenchmarkLargeClaimsToken` | Performance with large claims |
| `BenchmarkHighConcurrencyMixed` | Mixed concurrent operations |

### Custom Benchmarks

```go
func BenchmarkMyUseCase(b *testing.B) {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "benchmark-secret-key-32-bytes-minimum!!"
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    claims := &jwt.Claims{
        UserID:   "user123",
        Username: "benchmark_user",
        Role:     "admin",
    }

    b.ResetTimer()
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        token, _ := processor.Create(claims)
        _, _, _ = processor.Validate(token)
    }
}
```

---

## Memory Management

### Object Pooling

The library uses `sync.Pool` for frequently allocated objects:

- **Signing buffers**: Reused for token signing operations (`signingBufPool`, `sigBufPool`)
- **Claims objects**: Pooled to reduce GC pressure (`claimsPool`)
- **Parse buffers**: Reused for token parsing (`parseBufPool`, `decodeBufPool`)
- **Core structs**: Pooled for parsed token objects (`corePool`)
- **Token ID buffers**: Pooled for token ID generation (`tokenIDBufPool`)

### Memory Allocation Breakdown

| Component | Allocation Source |
|-----------|-------------------|
| Header encoding | Precomputed (zero allocation for standard headers) |
| Claims marshaling | JSON encoder allocation |
| Base64 encoding | Buffer pool allocation |
| Signature computation | HMAC hasher allocation |
| String building | strings.Builder allocation |

### Memory Optimization Features

1. **Precomputed Headers**: Standard JWT headers are pre-encoded to base64
2. **Buffer Pooling**: Signing buffers are pooled via `sync.Pool`
3. **Claims Pooling**: Claims objects are pooled for reuse

---

## Optimization Techniques

### 1. Reuse Processor

Create the processor once and reuse it:

```go
// GOOD: Global or dependency-injected processor
var processor *jwt.Processor

func init() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = os.Getenv("JWT_SECRET")
    processor, _ = jwt.New(cfg)
}

// BAD: Creating processor per request
func handler(w http.ResponseWriter, r *http.Request) {
    processor, _ := jwt.New(cfg) // Don't do this!
    defer processor.Close()
    // ...
}
```

### 2. Disable Unnecessary Features

```go
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key"

// Disable rate limiting if not needed
cfg.EnableRateLimit = false

// Minimize blacklist if not using revocation
// Note: EnableAutoCleanup is always true for the built-in store
// (enforced by normalizeConfig to prevent unbounded growth).
// To fully disable auto-cleanup, provide a custom BlacklistStore.
cfg.Blacklist.MaxSize = 1000 // Keep minimum; MaxSize must be > 0

processor, _ := jwt.New(cfg)
```

### 3. Use Appropriate Algorithm

| Use Case | Recommended Algorithm |
|----------|----------------------|
| High throughput, single service | HS256 |
| Multi-service, public/private key | ES256 |
| Maximum security | HS512 or ES512 |

### 4. Minimize Claims Size

```go
// GOOD: Minimal claims
claims := &jwt.Claims{
    UserID: "user123",
    Role:   "admin",
}

// BAD: Large claims (slower serialization)
claims := &jwt.Claims{
    UserID:      "user123",
    Permissions: make([]string, 100), // Large array
    Extra:       make(map[string]any, 50), // Large map
}
```

### 5. Pre-allocate Slices

```go
// GOOD: Pre-allocated
claims := &jwt.Claims{
    Permissions: []string{"read", "write", "delete"},
}

// Avoid growing slices dynamically
permissions := make([]string, 0, 3)
permissions = append(permissions, "read", "write", "delete")
```

### 6. Batch Operations

For bulk operations, consider batching:

```go
func validateTokens(processor *jwt.Processor, tokens []string) []jwt.Claims {
    results := make([]jwt.Claims, len(tokens))

    var wg sync.WaitGroup
    for i, token := range tokens {
        wg.Add(1)
        go func(idx int, t string) {
            defer wg.Done()
            claims, valid, _ := processor.Validate(t)
            if valid {
                results[idx] = claims
            }
        }(i, token)
    }
    wg.Wait()

    return results
}
```

---

## Profiling

### CPU Profiling

```bash
# Generate CPU profile
go test -bench=. -cpuprofile=cpu.out ./...

# Analyze
go tool pprof cpu.out

# Common pprof commands
# (pprof) top10
# (pprof) list SignedString
# (pprof) web
```

### Memory Profiling

```bash
# Generate memory profile
go test -bench=. -memprofile=mem.out ./...

# Analyze
go tool pprof mem.out

# Common commands
# (pprof) top10
# (pprof) list Create
```

### Continuous Profiling

```go
import (
    "net/http"
    _ "net/http/pprof"
)

func init() {
    // Enable pprof endpoint
    go http.ListenAndServe("localhost:6060", nil)
}

// Access profiles at:
// http://localhost:6060/debug/pprof/profile?seconds=30
// http://localhost:6060/debug/pprof/heap
```

### Trace Analysis

```bash
# Generate trace
go test -trace=trace.out ./...

# View trace
go tool trace trace.out
```

---

## Best Practices

### 1. Processor Lifecycle

```go
// Application startup
func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = os.Getenv("JWT_SECRET")
    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    // Pass processor to handlers
    http.Handle("/api", apiHandler(processor))
    http.ListenAndServe(":8080", nil)
}
```

### 2. Connection Pooling (Blacklist)

When using Redis-backed blacklist:

```go
// Redis-backed blacklist for distributed systems
cfg := jwt.DefaultConfig()
cfg.Blacklist.Store = redisStore // Custom BlacklistStore implementation
```

### 3. Asymmetric Key Caching

For asymmetric algorithms, keys are loaded once:

```go
// Load keys at startup
func loadKeys() (*rsa.PrivateKey, error) {
    keyData, err := os.ReadFile("private.pem")
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(keyData)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    rsaKey, ok := key.(*rsa.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("not an RSA private key")
    }
    return rsaKey, nil
}

// Use cached keys
func main() {
    privateKey, _ := loadKeys()

    cfg := jwt.DefaultConfig()
    cfg.SigningKey = privateKey
    cfg.SigningMethod = jwt.SigningMethodRS256

    processor, _ := jwt.New(cfg)
    defer processor.Close()
}
```

### 4. Graceful Shutdown

```go
func main() {
    processor, _ := jwt.New(cfg)

    // HTTP server setup...

    // Graceful shutdown
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    // Close processor (clears secret key from memory)
    processor.Close()
}
```

### 5. Monitoring

```go
// Expose metrics
func metricsHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        stats := map[string]interface{}{
            "processor_closed": processor.IsClosed(),
            "goroutines":       runtime.NumGoroutine(),
            // Add custom metrics
        }
        json.NewEncoder(w).Encode(stats)
    }
}
```

---

## Performance Anti-Patterns

### ❌ Creating Processor Per Request

```go
// BAD
func handler(w http.ResponseWriter, r *http.Request) {
    processor, _ := jwt.New(cfg)
    defer processor.Close()
    // This creates significant overhead
}
```

### ❌ Large Claims Objects

```go
// BAD
claims := &jwt.Claims{
    Extra: map[string]any{
        "data": hugeSlice, // Large data in claims
    },
}
```

### ❌ Blocking Operations in Hot Path

```go
// BAD
func handler(w http.ResponseWriter, r *http.Request) {
    claims, _, _ := processor.Validate(token)
    db.Query("SELECT * FROM users") // Database in hot path
}
```

### ❌ String Concatenation

```go
// BAD
token := header + "." + payload + "." + signature

// GOOD (library does this internally)
var builder strings.Builder
builder.Grow(totalLen)
builder.WriteString(header)
// ...
```

---

## Performance Tuning Checklist

- [ ] Processor created once at startup
- [ ] Processor closed on shutdown
- [ ] Rate limiting disabled if not needed
- [ ] Blacklist disabled if not using revocation
- [ ] Appropriate algorithm selected
- [ ] Minimal claims size
- [ ] Benchmarks run for critical paths
- [ ] Profiling enabled in development
- [ ] Memory limits understood

---
