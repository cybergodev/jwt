# JWT Library - Performance Guide

This guide provides performance characteristics and optimization techniques for production deployments.

## 🚀 Benchmark Results

Run benchmarks in your environment:

```bash
go test -bench=. -benchmem
```

Typical results on modern hardware:
- Token Creation: ~80,000 ops/sec
- Token Validation: ~90,000 ops/sec
- Memory per operation: 3-4 KB

## 🔧 Performance Optimization

### Reuse Processor Instances

Create a processor once and reuse it:

```go
// ✅ Reuse processor
processor, err := jwt.New(secretKey)
if err != nil {
    return err
}
defer processor.Close()

// Use for multiple operations
for _, token := range tokens {
    claims, valid, err := processor.ValidateToken(token)
    // Process claims...
}
```

### Choose Optimal Algorithm

```go
// HS256 is fastest
config := jwt.DefaultConfig()
config.SigningMethod = jwt.HS256

processor, err := jwt.New(secretKey, config)
```

### Concurrent Usage

The processor is safe for concurrent use:

```go
processor, err := jwt.New(secretKey)
defer processor.Close()

// Multiple goroutines can safely use the same processor
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(token string) {
        defer wg.Done()
        claims, valid, _ := processor.ValidateToken(token)
    }(tokens[i])
}
wg.Wait()
```
## 🎯 Configuration for Performance

### Optimal Settings

```go
config := jwt.DefaultConfig()
config.SigningMethod = jwt.HS256
config.AccessTokenTTL = 15 * time.Minute
config.RefreshTokenTTL = 24 * time.Hour

processor, err := jwt.New(secretKey, config)
```

### Blacklist Configuration

```go
blacklistConfig := jwt.DefaultBlacklistConfig()
blacklistConfig.MaxSize = 100000
blacklistConfig.CleanupInterval = 30 * time.Second

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

## 📊 Profiling

### Memory Profiling

```bash
go test -bench=BenchmarkTokenCreation -memprofile=mem.prof
go tool pprof mem.prof
```

### CPU Profiling

```bash
go test -bench=BenchmarkTokenCreation -cpuprofile=cpu.prof
go tool pprof cpu.prof
```

### Stress Testing

```bash
go test -bench=. -benchtime=60s -cpu=1,2,4,8
```

## 📋 Performance Checklist

- [ ] Reuse processor instances
- [ ] Use HS256 for best performance
- [ ] Configure appropriate TTL values
- [ ] Run benchmarks in your environment
- [ ] Profile memory and CPU usage
- [ ] Test concurrent workloads

---

For more details, see [API.md](API.md) and [BEST_PRACTICES.md](BEST_PRACTICES.md).
