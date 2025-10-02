# JWT Library - Complete Troubleshooting Guide

> **Expert Problem-Solving Resource** - Systematic diagnosis and resolution guide for all JWT library issues with production-ready solutions.

This comprehensive troubleshooting guide provides step-by-step diagnosis procedures, root cause analysis, and proven solutions for all common and advanced JWT library issues.

## 🚨 Emergency Quick Fixes

### Critical Issues (Production Down)

| Issue                         | Quick Fix                        | Time to Resolution |
|-------------------------------|----------------------------------|--------------------|
| **"invalid secret key"**      | Check key length ≥32 bytes       | 2 minutes          |
| **"token validation failed"** | Verify token format (3 parts)    | 3 minutes          |
| **"rate limit exceeded"**     | Increase rate limits temporarily | 1 minute           |
| **High memory usage**         | Restart with processor.Close()   | 5 minutes          |

### Emergency Diagnostic Commands

```bash
# Quick health check
go test -run TestSecurity -v

# Performance check
go test -bench=BenchmarkTokenCreation -benchmem -count=1

# Memory leak check
go test -run TestMemoryLeak -v
```

## 📋 Complete Troubleshooting Index

### 🔥 [Critical Errors](#-critical-errors)
- [Authentication Failures](#authentication-failures)
- [Token Validation Errors](#token-validation-errors)
- [Memory & Performance Issues](#memory--performance-issues)
- [Security Violations](#security-violations)

### ⚙️ [Configuration Problems](#-configuration-problems)
- [Secret Key Issues](#secret-key-issues)
- [TTL Configuration](#ttl-configuration)
- [Blacklist Problems](#blacklist-problems)
- [Rate Limiting Issues](#rate-limiting-issues)

### 🔧 [Integration Issues](#-integration-issues)
- [Framework Integration](#framework-integration)
- [Middleware Problems](#middleware-problems)
- [Concurrency Issues](#concurrency-issues)
- [Environment-Specific](#environment-specific)

### 📊 [Monitoring & Debugging](#-monitoring--debugging)
- [Diagnostic Tools](#diagnostic-tools)
- [Performance Profiling](#performance-profiling)
- [Log Analysis](#log-analysis)
- [Health Checks](#health-checks)

---

## 🔥 Critical Errors

### Authentication Failures

#### "invalid secret key" Error

**🚨 Symptoms:**
```
Error: invalid secret key
Code: ErrInvalidSecretKey
```

**🔍 Root Causes:**
1. **Key too short**: Less than 32 bytes
2. **Weak entropy**: Predictable patterns detected
3. **Common passwords**: Dictionary words or keyboard patterns
4. **Empty key**: Missing environment variable

**✅ Diagnostic Procedure:**
```go
// ✅ PRODUCTION: Comprehensive key validation
func validateSecretKey(key string) error {
    // Length check
    if len(key) < 32 {
        return fmt.Errorf("key too short: %d bytes (minimum: 32)", len(key))
    }

    // Entropy analysis
    entropy := calculateEntropy([]byte(key))
    if entropy < 4.0 {
        return fmt.Errorf("key entropy too low: %.2f (minimum: 4.0)", entropy)
    }

    // Pattern detection
    if hasWeakPatterns(key) {
        return fmt.Errorf("key contains weak patterns")
    }

    // Character diversity
    if !hasCharacterDiversity(key) {
        return fmt.Errorf("key lacks character diversity")
    }

    return nil
}

// ✅ PRODUCTION: Generate secure key
func generateSecureKey() string {
    key := make([]byte, 64) // 512 bits
    if _, err := rand.Read(key); err != nil {
        panic(err)
    }
    return base64.URLEncoding.EncodeToString(key)
}
```

**🛠️ Solutions:**
```go
// ❌ WRONG: Weak keys
secretKey := "password123"        // Dictionary word
secretKey := "aaaaaaaaaaaaaaaa"   // Repeated characters
secretKey := "qwertyuiop"         // Keyboard pattern

// ✅ CORRECT: Strong keys
secretKey := generateSecureKey()  // Cryptographically secure
secretKey := os.Getenv("JWT_SECRET_KEY") // From secure storage

// ✅ CORRECT: Key validation on startup
if err := validateSecretKey(secretKey); err != nil {
    log.Fatalf("Secret key validation failed: %v", err)
}
```

### Token Validation Errors

#### "invalid token" Error

**🚨 Symptoms:**
```
Error: invalid token
Code: ErrInvalidToken
HTTP Status: 401 Unauthorized
```

**🔍 Systematic Diagnosis:**
```go
// ✅ PRODUCTION: Advanced token diagnostics
func diagnoseToken(secretKey, tokenString string) *DiagnosticReport {
    report := &DiagnosticReport{
        Token:     tokenString,
        Timestamp: time.Now(),
    }

    // 1. Format validation
    parts := strings.Split(tokenString, ".")
    report.PartCount = len(parts)
    if len(parts) != 3 {
        report.AddError("Invalid format: expected 3 parts, got %d", len(parts))
        return report
    }

    // 2. Header analysis
    if header, err := decodeJWTHeader(parts[0]); err != nil {
        report.AddError("Header decode failed: %v", err)
    } else {
        report.Header = header
        report.Algorithm = header.Algorithm
    }

    // 3. Payload analysis
    if payload, err := decodeJWTPayload(parts[1]); err != nil {
        report.AddError("Payload decode failed: %v", err)
    } else {
        report.Payload = payload
        report.ExpiresAt = time.Unix(payload.ExpiresAt, 0)
        report.IssuedAt = time.Unix(payload.IssuedAt, 0)

        // Check expiration
        if time.Now().After(report.ExpiresAt) {
            report.AddError("Token expired: %v", report.ExpiresAt)
        }
    }

    // 4. Signature validation
    if err := validateSignature(parts, secretKey); err != nil {
        report.AddError("Signature validation failed: %v", err)
    }

    // 5. Blacklist check
    if isBlacklisted(tokenString) {
        report.AddError("Token is blacklisted")
    }

    return report
}

type DiagnosticReport struct {
    Token       string
    PartCount   int
    Header      *JWTHeader
    Payload     *JWTPayload
    Algorithm   string
    ExpiresAt   time.Time
    IssuedAt    time.Time
    Errors      []string
    Timestamp   time.Time
}

func (dr *DiagnosticReport) AddError(format string, args ...interface{}) {
    dr.Errors = append(dr.Errors, fmt.Sprintf(format, args...))
}

func (dr *DiagnosticReport) IsValid() bool {
    return len(dr.Errors) == 0
}
```

**🛠️ Common Solutions:**

1. **Token Format Issues:**
```go
// ❌ WRONG: Malformed token
token := "invalid.token"  // Missing signature part

// ✅ CORRECT: Proper token extraction
authHeader := r.Header.Get("Authorization")
if !strings.HasPrefix(authHeader, "Bearer ") {
    return errors.New("invalid authorization header format")
}
token := strings.TrimPrefix(authHeader, "Bearer ")
```

2. **Expiration Issues:**
```go
// ✅ CORRECT: Check expiration before validation
claims := jwt.Claims{
    ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
    IssuedAt:  jwt.NewNumericDate(time.Now()),
    NotBefore: jwt.NewNumericDate(time.Now()),
}
```

3. **Key Mismatch Issues:**
```go
// ✅ CORRECT: Consistent key usage
const secretKey = "same-key-for-create-and-validate"

// Create token
token, err := jwt.CreateToken(secretKey, claims)

// Validate token (use same key)
validClaims, valid, err := jwt.ValidateToken(secretKey, token)
```

### Memory & Performance Issues

#### High Memory Usage

**🚨 Symptoms:**
```
Memory usage continuously increasing
GC pressure high
Application becoming slow
```

**🔍 Diagnostic Commands:**
```bash
# Memory profiling
go test -bench=BenchmarkTokenCreation -memprofile=mem.prof
go tool pprof mem.prof

# Check for memory leaks
go test -run TestMemoryLeak -v

# Monitor memory in production
curl http://localhost:8080/debug/pprof/heap > heap.prof
```

**✅ Solutions:**
```go
// ✅ PRODUCTION: Proper resource cleanup
func main() {
    processor, err := jwt.New(secretKey)
    if err != nil {
        log.Fatal(err)
    }

    // CRITICAL: Always close processor
    defer processor.Close()

    // Graceful shutdown
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-c
        log.Println("Shutting down...")
        processor.Close() // Explicit cleanup
        os.Exit(0)
    }()

    // Application logic...
}

// ✅ PRODUCTION: Object pool management
func processTokensBatch(tokens []string) {
    // Use object pools to reduce allocations
    claims := getClaims()
    defer putClaims(claims)

    for _, token := range tokens {
        // Process token with pooled objects
        processToken(token, claims)

        // Reset claims for reuse
        resetClaims(claims)
    }
}
```

---

## ⚙️ Configuration Problems

### Rate Limiting Issues

#### "rate limit exceeded" Error

**🚨 Symptoms:**
```
Error: rate limit exceeded
HTTP Status: 429 Too Many Requests
```

**🛠️ Quick Solutions:**
```go
// ✅ PRODUCTION: Adjust rate limits for your traffic
config := jwt.RateLimitConfig{
    Enabled:           true,
    TokenCreationRate: 1000,  // Increase from default 100
    ValidationRate:    5000,  // Increase from default 1000
    LoginAttemptRate:  10,    // Increase from default 5
    CleanupInterval:   1 * time.Minute,
}

// ✅ PRODUCTION: Disable rate limiting temporarily (emergency only)
config := jwt.RateLimitConfig{
    Enabled: false, // ONLY for emergency situations
}
```

### Blacklist Problems

#### Tokens Not Being Revoked

**🔍 Diagnostic Steps:**
```go
// ✅ PRODUCTION: Verify blacklist functionality
func testBlacklistFunctionality(processor *jwt.Processor) {
    // Create test token
    claims := jwt.Claims{UserID: "test"}
    claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(60 * time.Minute))
    token, err := processor.CreateToken(claims)
    if err != nil {
        log.Fatalf("Token creation failed: %v", err)
    }

    // Verify token is valid
    _, valid, err := processor.ValidateToken(token)
    if !valid || err != nil {
        log.Fatalf("Token should be valid: valid=%t, err=%v", valid, err)
    }

    // Revoke token
    if err := processor.RevokeToken(token); err != nil {
        log.Fatalf("Token revocation failed: %v", err)
    }

    // Verify token is now invalid
    _, valid, err = processor.ValidateToken(token)
    if valid {
        log.Fatal("Token should be invalid after revocation")
    }

    log.Println("Blacklist functionality verified")
}
```

---

## 📊 Monitoring & Debugging

### Diagnostic Tools

#### Production Health Check

```go
// ✅ PRODUCTION: Comprehensive health check endpoint
func healthCheckHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        health := map[string]interface{}{
            "status":    "healthy",
            "timestamp": time.Now().UTC(),
            "version":   "1.0.0",
        }

        // Test token operations
        testClaims := jwt.Claims{
            UserID:    "health-check",
        }

        testClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))

        // Test token creation
        start := time.Now()
        token, err := processor.CreateToken(testClaims)
        createDuration := time.Since(start)

        if err != nil {
            health["status"] = "unhealthy"
            health["error"] = "token creation failed: " + err.Error()
            w.WriteHeader(http.StatusServiceUnavailable)
            json.NewEncoder(w).Encode(health)
            return
        }

        // Test token validation
        start = time.Now()
        _, valid, err := processor.ValidateToken(token)
        validateDuration := time.Since(start)

        if err != nil || !valid {
            health["status"] = "unhealthy"
            health["error"] = "token validation failed"
            w.WriteHeader(http.StatusServiceUnavailable)
            json.NewEncoder(w).Encode(health)
            return
        }

        // Performance metrics
        health["performance"] = map[string]interface{}{
            "create_duration_ms":   createDuration.Milliseconds(),
            "validate_duration_ms": validateDuration.Milliseconds(),
        }

        // System metrics
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        health["memory"] = map[string]interface{}{
            "alloc_mb":      m.Alloc / 1024 / 1024,
            "total_alloc_mb": m.TotalAlloc / 1024 / 1024,
            "sys_mb":        m.Sys / 1024 / 1024,
            "num_gc":        m.NumGC,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(health)
    }
}
```

### Performance Profiling

#### CPU and Memory Profiling

```go
// ✅ PRODUCTION: Enable profiling endpoints
import _ "net/http/pprof"

func enableProfiling() {
    go func() {
        log.Println("Profiling server starting on :6060")
        log.Println(http.ListenAndServe(":6060", nil))
    }()
}

// Usage:
// go tool pprof http://localhost:6060/debug/pprof/profile
// go tool pprof http://localhost:6060/debug/pprof/heap
```

---

## 🎯 Troubleshooting Checklist

### Pre-Production Validation

- [ ] **Secret Key Validation**
  - [ ] Key length ≥32 bytes
  - [ ] High entropy (>4.0)
  - [ ] No weak patterns
  - [ ] Stored securely (environment variables/vault)

- [ ] **Token Operations**
  - [ ] Token creation successful
  - [ ] Token validation working
  - [ ] Token revocation functional
  - [ ] Expiration handling correct

- [ ] **Performance Validation**
  - [ ] Benchmark tests passing
  - [ ] Memory usage acceptable
  - [ ] No memory leaks detected
  - [ ] Rate limits configured appropriately

### Production Monitoring

- [ ] **Health Checks**
  - [ ] Health check endpoint responding
  - [ ] Performance metrics within limits
  - [ ] Error rates acceptable
  - [ ] Memory usage stable

- [ ] **Alerting Setup**
  - [ ] High error rate alerts
  - [ ] Performance degradation alerts
  - [ ] Memory leak alerts
  - [ ] Rate limit exceeded alerts

---

Through these troubleshooting techniques, you can quickly identify and resolve various issues encountered when using the JWT library.
