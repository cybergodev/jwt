# JWT Library - Best Practices

Production-ready guidelines for using the JWT library securely and efficiently.

## Table of Contents

- [Security Best Practices](#security-best-practices)
- [Configuration Best Practices](#configuration-best-practices)
- [Token Lifecycle Management](#token-lifecycle-management)
- [Error Handling](#error-handling)
- [Production Deployment](#production-deployment)
- [Monitoring and Observability](#monitoring-and-observability)

---

## Security Best Practices

### Secret Key Management

```go
// ✅ GOOD: Load from environment variable
func getSecretKey() string {
    key := os.Getenv("JWT_SECRET_KEY")
    if key == "" {
        log.Fatal("JWT_SECRET_KEY environment variable is required")
    }
    if len(key) < 32 {
        log.Fatal("JWT_SECRET_KEY must be at least 32 bytes")
    }
    return key
}

// ❌ BAD: Hardcoded secret key
cfg := jwt.DefaultConfig()
cfg.SecretKey = "my-secret-key" // Never do this!
```

### Key Rotation Strategy

```go
type KeyRotator struct {
    currentKey  string
    previousKey string
    mu          sync.RWMutex
}

func (r *KeyRotator) Rotate(newKey string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.previousKey = r.currentKey
    r.currentKey = newKey
}

func (r *KeyRotator) GetCurrentKey() string {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.currentKey
}

// During rotation, try current key, fall back to previous
func validateWithRotation(processor *jwt.Processor, rotator *KeyRotator, token string) (jwt.Claims, bool, error) {
    // Try current key first
    claims, valid, err := processor.Validate(token)
    if valid {
        return claims, valid, nil
    }

    // If validation fails, might be token signed with previous key
    // Create temporary processor with previous key for migration period
    // ...
    return claims, false, err
}
```

### Token Expiration Guidelines

| Token Type | Recommended TTL | Maximum TTL |
|------------|-----------------|-------------|
| Access Token | 15 minutes | 1 hour |
| Refresh Token | 7 days | 30 days |
| Password Reset | 15 minutes | 1 hour |
| Email Verification | 24 hours | 7 days |
| API Key | Never expires | N/A |

```go
cfg := jwt.DefaultConfig()
cfg.AccessTokenTTL = 15 * time.Minute   // Short-lived access
cfg.RefreshTokenTTL = 7 * 24 * time.Hour // Week-long refresh
```

### Algorithm Selection

```go
// ✅ Recommended for most use cases (symmetric, single service)
cfg.SigningMethod = jwt.SigningMethodHS256

// ✅ Recommended for distributed systems (asymmetric, public/private key)
cfg.SigningMethod = jwt.SigningMethodES256

// ❌ Never use "none" algorithm
// The library rejects this automatically
```

| Use Case | Algorithm | Key Size |
|----------|-----------|----------|
| Single service, high throughput | HS256 | 256+ bits |
| Microservices, API gateway | ES256 | P-256 curve |
| Legacy systems | RS256 | 2048+ bits |
| Maximum security | HS512 or ES512 | 512+ bits |

---

## Configuration Best Practices

### Complete Production Configuration

```go
func NewProductionProcessor(secretKey string) (*jwt.Processor, error) {
    cfg := jwt.DefaultConfig()

    // Security settings
    cfg.SecretKey = secretKey
    cfg.SigningMethod = jwt.SigningMethodHS256

    // Token settings
    cfg.AccessTokenTTL = 15 * time.Minute
    cfg.RefreshTokenTTL = 7 * 24 * time.Hour
    cfg.Issuer = "my-app-production"

    // Blacklist settings
    cfg.Blacklist = jwt.BlacklistConfig{
        MaxSize:           100000,
        CleanupInterval:   5 * time.Minute,
        EnableAutoCleanup: true,
    }

    // Rate limiting (protect against brute force)
    cfg.EnableRateLimit = true
    cfg.RateLimitRate = 100
    cfg.RateLimitWindow = time.Minute

    return jwt.New(cfg)
}
```

### Environment-Specific Configuration

```go
func GetConfig(env string) jwt.Config {
    cfg := jwt.DefaultConfig()

    switch env {
    case "production":
        cfg.AccessTokenTTL = 15 * time.Minute
        cfg.EnableRateLimit = true
        cfg.Blacklist.MaxSize = 100000

    case "staging":
        cfg.AccessTokenTTL = 30 * time.Minute
        cfg.EnableRateLimit = true
        cfg.Blacklist.MaxSize = 10000

    case "development":
        cfg.AccessTokenTTL = 1 * time.Hour
        cfg.EnableRateLimit = false
        cfg.Blacklist.MaxSize = 1000

    default:
        log.Fatalf("unknown environment: %s", env)
    }

    cfg.SecretKey = os.Getenv("JWT_SECRET_KEY")
    return cfg
}
```

---

## Token Lifecycle Management

### Token Creation Pattern

```go
func (s *AuthService) CreateSession(userID string) (*Session, error) {
    // 1. Create minimal claims
    claims := &jwt.Claims{
        UserID:    userID,
        SessionID: generateSessionID(),
    }

    // 2. Create tokens
    accessToken, err := s.processor.Create(claims)
    if err != nil {
        return nil, fmt.Errorf("failed to create access token: %w", err)
    }

    refreshToken, err := s.processor.CreateRefresh(claims)
    if err != nil {
        return nil, fmt.Errorf("failed to create refresh token: %w", err)
    }

    // 3. Return session
    return &Session{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresAt:    time.Now().Add(s.cfg.AccessTokenTTL),
    }, nil
}
```

### Token Refresh Pattern

```go
func (s *AuthService) RefreshAccessToken(refreshToken string) (string, error) {
    // 1. Validate refresh token
    claims, valid, err := s.processor.Validate(refreshToken)
    if err != nil || !valid {
        return "", errors.New("invalid refresh token")
    }

    // 2. Check if user is still active (optional)
    if !s.isUserActive(claims.UserID) {
        s.processor.Revoke(refreshToken)
        return "", errors.New("user account disabled")
    }

    // 3. Create new access token
    newClaims := &jwt.Claims{
        UserID:    claims.UserID,
        SessionID: claims.SessionID,
    }

    return s.processor.Create(newClaims)
}
```

### Token Revocation Pattern

```go
func (s *AuthService) Logout(tokenString string) error {
    // 1. Revoke the token directly (Revoke parses the token internally,
    //    so it works even with expired tokens)
    if err := s.processor.Revoke(tokenString); err != nil {
        return fmt.Errorf("failed to revoke token: %w", err)
    }

    return nil
}
```

---

## Error Handling

### Comprehensive Error Handling

```go
func (h *Handler) handleTokenValidation(token string) (*jwt.Claims, error) {
    claims, valid, err := h.processor.Validate(token)

    if err != nil {
        switch {
        case errors.Is(err, jwt.ErrTokenExpired):
            // Token expired - suggest refresh
            return nil, &APIError{
                Code:    "TOKEN_EXPIRED",
                Message: "Token has expired, please refresh",
                Status:  http.StatusUnauthorized,
            }

        case errors.Is(err, jwt.ErrTokenRevoked):
            // Token revoked - force re-login
            return nil, &APIError{
                Code:    "TOKEN_REVOKED",
                Message: "Token has been revoked",
                Status:  http.StatusUnauthorized,
            }

        case errors.Is(err, jwt.ErrTokenNotValidYet):
            // Clock skew issue
            return nil, &APIError{
                Code:    "TOKEN_NOT_VALID_YET",
                Message: "Token is not yet valid",
                Status:  http.StatusUnauthorized,
            }

        case errors.Is(err, jwt.ErrTokenInvalidIssuer):
            // Potential security issue
            h.logger.Warn("invalid issuer in token", "token", token[:20])
            return nil, &APIError{
                Code:    "INVALID_TOKEN",
                Message: "Invalid token",
                Status:  http.StatusUnauthorized,
            }

        case errors.Is(err, jwt.ErrRateLimitExceeded):
            // Rate limit hit
            return nil, &APIError{
                Code:    "RATE_LIMITED",
                Message: "Too many requests, please try again later",
                Status:  http.StatusTooManyRequests,
            }

        case errors.Is(err, jwt.ErrProcessorClosed):
            // Server shutting down
            return nil, &APIError{
                Code:    "SERVICE_UNAVAILABLE",
                Message: "Service temporarily unavailable",
                Status:  http.StatusServiceUnavailable,
            }

        default:
            // Generic error
            return nil, &APIError{
                Code:    "INVALID_TOKEN",
                Message: "Invalid token",
                Status:  http.StatusUnauthorized,
            }
        }
    }

    if !valid {
        return nil, &APIError{
            Code:    "INVALID_TOKEN",
            Message: "Token validation failed",
            Status:  http.StatusUnauthorized,
        }
    }

    return &claims, nil
}
```

### Logging Best Practices

```go
func (h *Handler) validateToken(token string) (*jwt.Claims, error) {
    claims, valid, err := h.processor.Validate(token)

    if err != nil {
        // Log security-relevant events
        switch {
        case errors.Is(err, jwt.ErrTokenRevoked):
            h.logger.Warn("revoked token used",
                "user_id", claims.UserID,
                "token_id", claims.ID,
            )

        case errors.Is(err, jwt.ErrTokenInvalidIssuer):
            h.logger.Warn("invalid issuer claim",
                "issuer", claims.Issuer,
                "expected", h.cfg.Issuer,
            )
        }

        // Never log the actual token or secret key
        return nil, err
    }

    return &claims, nil
}
```

---

## Production Deployment

### Health Check

```go
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
    // Check processor status
    if h.processor.IsClosed() {
        http.Error(w, "processor closed", http.StatusServiceUnavailable)
        return
    }

    // Basic health check
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]bool{
        "healthy": true,
    })
}
```

### Graceful Shutdown

```go
func main() {
    processor, _ := jwt.New(cfg)

    server := &http.Server{Addr: ":8080"}

    // Handle shutdown signals
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-quit
        log.Println("Shutting down...")

        // 1. Stop accepting new connections
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        server.Shutdown(ctx)

        // 2. Close JWT processor (clears secret key)
        if err := processor.Close(); err != nil {
            log.Printf("Error closing processor: %v", err)
        }

        log.Println("Shutdown complete")
    }()

    server.ListenAndServe()
}
```

### Container Deployment

```dockerfile
# Dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o server ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/server .

# Run as non-root user
RUN adduser -D -u 1000 appuser
USER appuser

EXPOSE 8080
CMD ["./server"]
```

```yaml
# kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  template:
    spec:
      containers:
      - name: auth
        image: auth-service:latest
        env:
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: jwt-secrets
              key: secret-key
        resources:
          limits:
            memory: "256Mi"
            cpu: "500m"
          requests:
            memory: "128Mi"
            cpu: "100m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

---

## Monitoring and Observability

### Metrics Collection

```go
type MetricsMiddleware struct {
    processor    *jwt.Processor
    tokensCreated    prometheus.Counter
    tokensValidated  prometheus.Counter
    tokensRevoked    prometheus.Counter
    validationErrors *prometheus.CounterVec
}

func (m *MetricsMiddleware) Create(claims jwt.CustomClaims) (string, error) {
    token, err := m.processor.Create(claims)
    if err == nil {
        m.tokensCreated.Inc()
    }
    return token, err
}

func (m *MetricsMiddleware) Validate(token string) (jwt.Claims, bool, error) {
    claims, valid, err := m.processor.Validate(token)
    m.tokensValidated.Inc()

    if err != nil {
        m.validationErrors.WithLabelValues(err.Error()).Inc()
    }

    return claims, valid, err
}
```

### Logging Structured Events

```go
type LoggingMiddleware struct {
    processor *jwt.Processor
    logger    *slog.Logger
}

func (m *LoggingMiddleware) Validate(token string) (jwt.Claims, bool, error) {
    start := time.Now()
    claims, valid, err := m.processor.Validate(token)
    duration := time.Since(start)

    // Log validation event
    if err != nil {
        m.logger.Warn("token validation failed",
            "valid", valid,
            "duration_ms", duration.Milliseconds(),
            "error", err,
        )
    } else {
        m.logger.Info("token validated",
            "user_id", claims.UserID,
            "valid", valid,
            "duration_ms", duration.Milliseconds(),
        )
    }

    return claims, valid, err
}
```

---

## Checklist

### Security Checklist
- [ ] Secret key loaded from environment variable
- [ ] Secret key is at least 32 bytes
- [ ] Access token TTL ≤ 15 minutes
- [ ] Algorithm explicitly configured
- [ ] Rate limiting enabled in production
- [ ] Token revocation implemented
- [ ] Graceful shutdown implemented

### Operational Checklist
- [ ] Health check endpoint implemented
- [ ] Metrics collection enabled
- [ ] Structured logging implemented
- [ ] Error handling comprehensive
- [ ] Graceful shutdown implemented
- [ ] Container running as non-root
- [ ] Resource limits configured

---
