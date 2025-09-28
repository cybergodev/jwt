# JWT Library - Production Best Practices

> **Production Deployment Guide** - Proven practices for secure, high-performance JWT implementation in production environments.

This comprehensive guide provides battle-tested best practices for deploying the JWT library in production, covering security, performance, monitoring, and operational excellence.

## 🎯 Quick Start Checklist

Before deploying to production, ensure you've completed these critical steps:

- [ ] **Secret Key**: Generated with cryptographic randomness (≥32 bytes)
- [ ] **Environment Variables**: Secrets stored securely, not in code
- [ ] **Token TTL**: Short-lived access tokens (≤15 minutes)
- [ ] **Rate Limiting**: Configured for your traffic patterns
- [ ] **Monitoring**: Error rates and performance metrics tracked
- [ ] **Blacklist**: Token revocation system enabled
- [ ] **Resource Cleanup**: Processor.Close() called on shutdown

---

## 🔐 Security Excellence

### Cryptographic Key Management

#### 1. Secure Key Generation

```go
// ✅ PRODUCTION: Cryptographically secure key generation
func generateProductionSecretKey() (string, error) {
    // Use 64 bytes (512 bits) for maximum security
    keyBytes := make([]byte, 64)

    // Use crypto/rand for cryptographic security
    if _, err := rand.Read(keyBytes); err != nil {
        return "", fmt.Errorf("failed to generate secure key: %w", err)
    }

    // Base64 encode for storage
    key := base64.URLEncoding.EncodeToString(keyBytes)

    // Validate key strength before returning
    if err := validateKeyStrength(key); err != nil {
        return "", fmt.Errorf("generated key failed validation: %w", err)
    }

    return key, nil
}

// ✅ PRODUCTION: Comprehensive key validation
func validateKeyStrength(key string) error {
    // Length validation (minimum 32 bytes)
    if len(key) < 32 {
        return fmt.Errorf("key too short: %d bytes, minimum 32 required", len(key))
    }

    // Entropy validation using the library's built-in security checks
    keyBytes := []byte(key)
    if security.IsWeakKey(keyBytes) {
        return fmt.Errorf("key failed security validation: insufficient entropy or weak patterns detected")
    }

    return nil
}

// ✅ PRODUCTION: Key generation CLI tool
func main() {
    if len(os.Args) > 1 && os.Args[1] == "generate-key" {
        key, err := generateProductionSecretKey()
        if err != nil {
            log.Fatalf("Key generation failed: %v", err)
        }

        fmt.Printf("Generated secure JWT key:\n%s\n", key)
        fmt.Println("\nAdd this to your environment variables:")
        fmt.Printf("export JWT_SECRET_KEY='%s'\n", key)
        return
    }

    // Regular application startup...
}
```

#### 2. Secure Key Storage & Retrieval

```go
// ✅ PRODUCTION: Environment-based key management
func getSecretKeyFromEnvironment() (string, error) {
    key := os.Getenv("JWT_SECRET_KEY")
    if key == "" {
        return "", fmt.Errorf("JWT_SECRET_KEY environment variable not set")
    }

    // Validate key on every startup
    if err := validateKeyStrength(key); err != nil {
        return "", fmt.Errorf("environment key validation failed: %w", err)
    }

    return key, nil
}

// ✅ PRODUCTION: HashiCorp Vault integration
func getSecretKeyFromVault(vaultAddr, vaultToken, keyPath string) (string, error) {
    config := vault.DefaultConfig()
    config.Address = vaultAddr

    client, err := vault.NewClient(config)
    if err != nil {
        return "", fmt.Errorf("failed to create vault client: %w", err)
    }

    client.SetToken(vaultToken)

    // Read secret from Vault
    secret, err := client.Logical().Read(keyPath)
    if err != nil {
        return "", fmt.Errorf("failed to read secret from vault: %w", err)
    }

    if secret == nil || secret.Data == nil {
        return "", fmt.Errorf("secret not found at path: %s", keyPath)
    }

    keyValue, exists := secret.Data["key"]
    if !exists {
        return "", fmt.Errorf("key field not found in secret")
    }

    key, ok := keyValue.(string)
    if !ok {
        return "", fmt.Errorf("key value is not a string")
    }

    // Validate retrieved key
    if err := validateKeyStrength(key); err != nil {
        return "", fmt.Errorf("vault key validation failed: %w", err)
    }

    return key, nil
}

// ✅ PRODUCTION: AWS Secrets Manager integration
func getSecretKeyFromAWS(secretName, region string) (string, error) {
    sess, err := session.NewSession(&aws.Config{
        Region: aws.String(region),
    })
    if err != nil {
        return "", fmt.Errorf("failed to create AWS session: %w", err)
    }

    svc := secretsmanager.New(sess)

    result, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
        SecretId: aws.String(secretName),
    })
    if err != nil {
        return "", fmt.Errorf("failed to retrieve secret: %w", err)
    }

    if result.SecretString == nil {
        return "", fmt.Errorf("secret value is empty")
    }

    key := *result.SecretString

    // Validate retrieved key
    if err := validateKeyStrength(key); err != nil {
        return "", fmt.Errorf("AWS secret key validation failed: %w", err)
    }

    return key, nil
}
```

#### 3. Production Key Rotation Strategy

```go
// ✅ PRODUCTION: Advanced key rotation manager
type ProductionKeyManager struct {
    currentKey    string
    previousKey   string
    processor     *jwt.Processor
    keyVersion    int
    rotationTime  time.Time
    mu            sync.RWMutex

    // Key rotation configuration
    rotationInterval time.Duration
    gracePeriod      time.Duration

    // Monitoring
    rotationCount    int64
    lastRotationTime time.Time
}

func NewProductionKeyManager(initialKey string, rotationInterval time.Duration) (*ProductionKeyManager, error) {
    if err := validateKeyStrength(initialKey); err != nil {
        return nil, fmt.Errorf("initial key validation failed: %w", err)
    }

    // Create processor with rate limiting disabled for key management
    config := jwt.DefaultConfig()
    config.EnableRateLimit = false // Key management doesn't need rate limiting

    processor, err := jwt.New(initialKey, config)
    if err != nil {
        return nil, fmt.Errorf("failed to create processor: %w", err)
    }

    return &ProductionKeyManager{
        currentKey:       initialKey,
        processor:        processor,
        keyVersion:       1,
        rotationTime:     time.Now(),
        rotationInterval: rotationInterval,
        gracePeriod:      30 * time.Minute, // 30-minute grace period
    }, nil
}

func (pkm *ProductionKeyManager) RotateKey() error {
    pkm.mu.Lock()
    defer pkm.mu.Unlock()

    // Generate new key
    newKey, err := generateProductionSecretKey()
    if err != nil {
        return fmt.Errorf("new key generation failed: %w", err)
    }

    // Create new processor with new key
    config := jwt.DefaultConfig()
    config.EnableRateLimit = false // Key management doesn't need rate limiting

    newProcessor, err := jwt.New(newKey, config)
    if err != nil {
        return fmt.Errorf("new processor creation failed: %w", err)
    }

    // Store previous key for grace period validation
    pkm.previousKey = pkm.currentKey
    pkm.currentKey = newKey

    // Close old processor and update
    if pkm.processor != nil {
        pkm.processor.Close()
    }
    pkm.processor = newProcessor

    // Update metadata
    pkm.keyVersion++
    pkm.rotationTime = time.Now()
    pkm.rotationCount++
    pkm.lastRotationTime = time.Now()

    log.Printf("Key rotation completed: version %d", pkm.keyVersion)
    return nil
}

func (pkm *ProductionKeyManager) ValidateToken(tokenString string) (*jwt.Claims, bool, error) {
    pkm.mu.RLock()
    defer pkm.mu.RUnlock()

    // Try current key first
    claims, valid, err := pkm.processor.ValidateToken(tokenString)
    if err == nil && valid {
        return claims, valid, nil
    }

    // If current key fails and we have a previous key, try it (grace period)
    if pkm.previousKey != "" && time.Since(pkm.rotationTime) < pkm.gracePeriod {
        config := jwt.DefaultConfig()
        config.EnableRateLimit = false // Key validation doesn't need rate limiting

        prevProcessor, err := jwt.New(pkm.previousKey, config)
        if err != nil {
            return nil, false, fmt.Errorf("failed to create previous key processor: %w", err)
        }
        defer prevProcessor.Close()

        claims, valid, err := prevProcessor.ValidateToken(tokenString)
        if err == nil && valid {
            log.Printf("Token validated with previous key (grace period)")
            return claims, valid, nil
        }
    }

    return nil, false, fmt.Errorf("token validation failed with both current and previous keys")
}

// Automatic key rotation
func (pkm *ProductionKeyManager) StartAutoRotation(ctx context.Context) {
    ticker := time.NewTicker(pkm.rotationInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := pkm.RotateKey(); err != nil {
                log.Printf("Automatic key rotation failed: %v", err)
                // Alert monitoring system
                alertKeyRotationFailure(err)
            }
        case <-ctx.Done():
            log.Println("Key rotation stopped")
            return
        }
    }
}
```
### Token Lifecycle Security

#### 1. Optimal Token TTL Configuration

```go
// ✅ PRODUCTION: Security-optimized TTL settings
func createSecureTokenConfig() jwt.Config {
    return jwt.Config{
        AccessTokenTTL:  10 * time.Minute,     // Very short-lived for security
        RefreshTokenTTL: 24 * time.Hour,       // Daily refresh requirement
        Issuer:          "secure-app-v1.0",    // Version-specific issuer
        SigningMethod:   jwt.SigningMethodHS512, // Strongest HMAC algorithm
        Timezone:        time.UTC,             // Always use UTC
    }
}

// ✅ PRODUCTION: Dynamic TTL based on user risk profile
func createRiskBasedConfig(userRiskLevel string) jwt.Config {
    config := jwt.DefaultConfig()

    switch userRiskLevel {
    case "high-risk":
        config.AccessTokenTTL = 5 * time.Minute   // Very short for high-risk users
        config.RefreshTokenTTL = 4 * time.Hour    // Frequent re-authentication
    case "medium-risk":
        config.AccessTokenTTL = 15 * time.Minute  // Standard duration
        config.RefreshTokenTTL = 24 * time.Hour   // Daily refresh
    case "low-risk":
        config.AccessTokenTTL = 30 * time.Minute  // Longer for trusted users
        config.RefreshTokenTTL = 7 * 24 * time.Hour // Weekly refresh
    default:
        config.AccessTokenTTL = 15 * time.Minute  // Default to medium security
        config.RefreshTokenTTL = 24 * time.Hour
    }

    return config
}
```

---

## 🚀 Performance Optimization

### High-Throughput Configuration

```go
// ✅ PRODUCTION: High-performance processor setup
func createHighPerformanceProcessor(secretKey string) (*jwt.Processor, error) {
    // Optimized blacklist for high throughput
    blacklistConfig := jwt.BlacklistConfig{
        MaxSize:           1000000,          // 1M tokens for high-volume apps
        CleanupInterval:   1 * time.Minute,  // Frequent cleanup
        EnableAutoCleanup: true,
        StoreType:        "memory",          // Fastest storage
    }

    // Performance-optimized JWT config
    config := jwt.Config{
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 24 * time.Hour,
        SigningMethod:   jwt.SigningMethodHS256, // Fastest algorithm
    }

    // Enable rate limiting for production use
    config.EnableRateLimit = true
    config.RateLimit = &jwt.RateLimitConfig{
        Enabled:           true,
        TokenCreationRate: 100,
        ValidationRate:    1000,
        LoginAttemptRate:  5,
        PasswordResetRate: 3,
        CleanupInterval:   5 * time.Minute,
    }

    return jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
}

// ✅ PRODUCTION: Connection pooling for distributed systems
type ProcessorPool struct {
    processors []*jwt.Processor
    current    int64
    mu         sync.RWMutex
}

func NewProcessorPool(secretKey string, poolSize int) (*ProcessorPool, error) {
    processors := make([]*jwt.Processor, poolSize)

    for i := 0; i < poolSize; i++ {
        processor, err := createHighPerformanceProcessor(secretKey)
        if err != nil {
            return nil, fmt.Errorf("failed to create processor %d: %w", i, err)
        }
        processors[i] = processor
    }

    return &ProcessorPool{processors: processors}, nil
}

func (pp *ProcessorPool) GetProcessor() *jwt.Processor {
    pp.mu.RLock()
    defer pp.mu.RUnlock()

    // Round-robin selection
    index := atomic.AddInt64(&pp.current, 1) % int64(len(pp.processors))
    return pp.processors[index]
}
```

---

## 🏭 Production Deployment

### Environment Configuration

```go
// ✅ PRODUCTION: Complete environment setup
func initializeProductionJWT() (*jwt.Processor, error) {
    // 1. Load configuration from environment
    secretKey, err := getSecretKeyFromEnvironment()
    if err != nil {
        return nil, fmt.Errorf("secret key loading failed: %w", err)
    }

    // 2. Create production-ready configuration
    config := jwt.Config{
        SecretKey:       secretKey,
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 24 * time.Hour,
        Issuer:          os.Getenv("APP_NAME") + "-" + os.Getenv("APP_VERSION"),
        SigningMethod:   jwt.SigningMethodHS256,
    }

    // 3. Configure blacklist for token revocation
    blacklistConfig := jwt.BlacklistConfig{
        MaxSize:           getEnvInt("JWT_BLACKLIST_SIZE", 100000),
        CleanupInterval:   getEnvDuration("JWT_CLEANUP_INTERVAL", 5*time.Minute),
        EnableAutoCleanup: true,
    }

    // 4. Enable rate limiting for production
    rateLimitConfig := jwt.RateLimitConfig{
        Enabled:           true,
        TokenCreationRate: getEnvInt("JWT_TOKEN_RATE", 100),
        ValidationRate:    getEnvInt("JWT_VALIDATION_RATE", 1000),
        LoginAttemptRate:  getEnvInt("JWT_LOGIN_RATE", 5),
        PasswordResetRate: getEnvInt("JWT_RESET_RATE", 3),
        CleanupInterval:   getEnvDuration("JWT_RATE_CLEANUP", 5*time.Minute),
    }

    config.EnableRateLimit = true
    config.RateLimit = &rateLimitConfig

    // 5. Create processor with full configuration
    processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
    if err != nil {
        return nil, fmt.Errorf("processor creation failed: %w", err)
    }

    log.Printf("JWT processor initialized successfully")
    return processor, nil
}

// Helper functions for environment configuration
func getEnvInt(key string, defaultValue int) int {
    if value := os.Getenv(key); value != "" {
        if intValue, err := strconv.Atoi(value); err == nil {
            return intValue
        }
    }
    return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
    if value := os.Getenv(key); value != "" {
        if duration, err := time.ParseDuration(value); err == nil {
            return duration
        }
    }
    return defaultValue
}
```

---

## 🎯 Production Checklist

### Pre-Deployment Validation

- [ ] **Security Validation**
  - [ ] Secret key ≥32 bytes with high entropy
  - [ ] Keys stored in secure key management system
  - [ ] Token TTL configured appropriately (≤15 min access, ≤24h refresh)
  - [ ] Rate limiting enabled and configured
  - [ ] All security tests passing

- [ ] **Performance Validation**
  - [ ] Benchmark tests show acceptable performance (>50K ops/sec)
  - [ ] Memory usage within acceptable limits
  - [ ] Processor pool configured for expected load
  - [ ] Blacklist size appropriate for user base

- [ ] **Operational Readiness**
  - [ ] Monitoring and alerting configured
  - [ ] Error handling and logging implemented
  - [ ] Graceful shutdown procedures in place
  - [ ] Key rotation procedures documented and tested


---

**🏆 Following these production best practices ensures your JWT implementation is secure, performant, and operationally excellent. Regular review and updates of these practices are essential for maintaining security posture.**

