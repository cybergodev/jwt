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

Representative figures (laptop CPUs vary ~15-20% run-to-run from thermal
throttling; allocations are deterministic). HMAC-SHA256 (HS256), minimal claims.

| Operation | Time | Memory | Allocations |
|-----------|------|--------|-------------|
| Token Creation | ~1.1µs | ~401 B | 2 allocs |
| Token Validation | ~2.8µs | ~241 B | 8 allocs |
| Create + Validate | ~4.1µs | ~645 B | 10 allocs |
| Concurrent Creation | ~660ns | ~408 B | 2 allocs |
| Concurrent Validation | ~505ns | ~242 B | 8 allocs |
| Blacklist Validation | ~2.7µs | ~241 B | 8 allocs |

### Throughput

| Scenario | Operations/sec |
|----------|----------------|
| Single-threaded token creation | ~880,000 |
| Single-threaded validation | ~360,000 |
| Concurrent mixed operations (22 cores) | ~1,000,000+ |

### Algorithm Comparison

| Algorithm | Create + Validate | Notes |
|-----------|-------------------|-------|
| HS256 | ~3.8µs | Fastest, recommended for HMAC |
| HS384 | ~4.9µs | More secure, slightly slower |
| HS512 | ~5.0µs | Most secure HMAC option |
| RS256 | ~0.9ms | Asymmetric; RSA-2048 signing dominates the cost |
| ES256 | ~110µs | Asymmetric, much faster than RSA |

> HS figures come from `BenchmarkDifferentSigningMethods`, which covers the
> HMAC family only. RS256/ES256 figures come from an equivalent Create +
> Validate benchmark (2048-bit RSA / P-256 key) — asymmetric algorithms are
> not part of `BenchmarkDifferentSigningMethods`.

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
| `BenchmarkDifferentSigningMethods` | Algorithm comparison (HS256/HS384/HS512 only) |
| `BenchmarkLargeClaimsToken` | Performance with large claims |
| `BenchmarkHighConcurrencyMixed` | Mixed concurrent operations |
| `BenchmarkMemoryUsage` | Memory allocation profiling |
| `BenchmarkProcessorCreation` | Processor initialization overhead |

### Custom Benchmarks

```go
func BenchmarkMyUseCase(b *testing.B) {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~"
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

- **Signing buffers**: Reused for token signing operations (`signingBufPool`, `encoderBufPool`)
- **Claims objects**: Pooled to reduce GC pressure (`claimsPool`)
- **Parse buffers**: Reused for token parsing (`parseBufPool`, `decodeBufPool`)
- **Core structs**: Pooled for parsed token objects (`corePool`)
- **Hash.Hash instances**: Pooled for HMAC, RSA, and ECDSA operations (per-method hash pools)
- **ECDSA big.Int/sig buffers**: Pooled for signature encoding/decoding (`bigIntPool`, `sigPool`)

### Memory Allocation Breakdown

| Component | Allocation Source |
|-----------|-------------------|
| Header encoding | Precomputed base64 constants (zero allocation for standard headers) |
| Claims marshaling | Appended into the pooled signing buffer via `Claims.AppendJSON` (pooled `json.Encoder` fallback for other claims types) |
| Base64 encoding | Encoded in place into the pooled signing buffer |
| Signature computation | Pooled HMAC hashers (built once per key, reused) |
| Token string | A single string allocation for the final token |

### Memory Optimization Features

1. **Precomputed Headers**: Standard JWT headers are pre-encoded to base64
2. **Buffer Pooling**: Signing buffers are pooled via `sync.Pool`
3. **Claims Pooling**: Claims objects are pooled for reuse

### Parse-Path CPU Fast-Paths

Profiling (baseline → pprof → optimize → verify) drove these validate-path
optimizations:

1. **SIMD token split**: `fastSplit3` uses `strings.IndexByte` (vectorized on
   amd64/arm64) instead of a byte-by-byte loop to find the two `.` separators —
   ~2.3x faster in isolation.
2. **Insecure-algorithm fast path**: `isInsecureAlgorithm` short-circuits on the
   read-only method registry (`globalMethods`), so the common case — a valid
   standard algorithm — returns in one O(1) lookup instead of an 11-entry
   case-insensitive scan on every validation.
3. **Specialized claims decoder** (`claims_json.go`): a strict, allocation-light
   JSON scanner fills the known `Claims` fields directly, replacing
   `encoding/json`'s reflection decode on the payload hot path. Any input the
   scanner cannot fully verify — escaped strings, unusual numbers, trailing
   garbage, ... — falls back to `encoding/json`, which owns the authoritative
   decoded values and error messages (pinned by differential tests and fuzzing).

Items 1–2 cut `BenchmarkTokenValidation` ~11% (interleaved A/B, both orderings)
when they landed, with no change in allocations. Item 3 later removed the
payload's `encoding/json` decode entirely, dropping validation allocations
from 11 to 8 per operation. The remaining validate CPU is the claims scanner,
the header decode, and the SHA-256 HMAC.

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
cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~"

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
// BAD: intermediate strings at every step
token := header + "." + payload + "." + signature

// GOOD (what the library does internally): assemble "header.payload" in a
// pooled byte buffer with capacity reserved for the signature, write the
// signature in place right after the trailing '.', and convert to a string
// once — one allocation for the whole token, no intermediate strings.
buf := make([]byte, 0, len(header)+1+len(payload)+1+sigReserve) // pooled
buf = append(buf, header...)
buf = append(buf, '.')
buf = append(buf, payload...)
buf = append(buf, '.')
// ... signature is base64-encoded directly after the trailing '.'
token := string(buf) // the only string allocation
```

---

## Performance Tuning Checklist

- [ ] Processor created once at startup
- [ ] Processor closed on shutdown
- [ ] Rate limiting disabled if not needed
- [ ] Blacklist size minimized if not using revocation (it cannot be disabled, only sized down)
- [ ] Appropriate algorithm selected
- [ ] Minimal claims size
- [ ] Benchmarks run for critical paths
- [ ] Profiling enabled in development
- [ ] Memory limits understood

---
