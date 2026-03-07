# JWT Library - API Reference

Complete API documentation for the `github.com/cybergodev/jwt` library.

## Table of Contents

- [Core Types](#core-types)
- [Configuration](#configuration)
- [Processor Methods](#processor-methods)
- [Claims Types](#claims-types)
- [Error Types](#error-types)
- [Interfaces](#interfaces)
- [Constants](#constants)

---

## Core Types

### Processor

The main type for JWT operations. Thread-safe and reusable.

```go
type Processor struct {
    // Contains filtered or unexported fields
}
```

#### Creation

```go
// Create with configuration
func New(cfg ...Config) (*Processor, error)

// Configuration with defaults
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key-at-least-32-bytes-long"
processor, err := jwt.New(cfg)
if err != nil {
    log.Fatal(err)
}
defer processor.Close()
```

---

## Configuration

### Config

Main configuration struct for the Processor.

```go
type Config struct {
    // Signing configuration (choose one)
    SecretKey       string        // For HMAC algorithms (minimum 32 bytes)
    SigningKey      any           // For asymmetric algorithms (*rsa.PrivateKey or *ecdsa.PrivateKey)
    VerificationKey any           // Optional: public key for verification only
    SigningMethod   SigningMethod // HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

    // Token configuration
    AccessTokenTTL  time.Duration // Default: 15 minutes
    RefreshTokenTTL time.Duration // Default: 7 days
    Issuer          string        // Default: "jwt-service"

    // Blacklist configuration (embedded)
    Blacklist BlacklistConfig

    // Rate limiting
    EnableRateLimit bool              // Default: false
    RateLimitRate   int               // Default: 100
    RateLimitWindow time.Duration     // Default: 1 minute
    RateLimiter     RateLimitProvider // Optional: custom rate limiter
}
```

### DefaultConfig

Returns a Config with sensible defaults.

```go
func DefaultConfig() Config
```

**Default Values:**

| Field | Default Value |
|-------|---------------|
| `AccessTokenTTL` | 15 minutes |
| `RefreshTokenTTL` | 7 days |
| `Issuer` | "jwt-service" |
| `SigningMethod` | HS256 |
| `RateLimitRate` | 100 |
| `RateLimitWindow` | 1 minute |
| `Blacklist` | DefaultBlacklistConfig() |

### BlacklistConfig

Configuration for the token blacklist.

```go
type BlacklistConfig struct {
    MaxSize           int           // Maximum entries (default: 10000)
    CleanupInterval   time.Duration // Cleanup interval (default: 5 minutes)
    EnableAutoCleanup bool          // Enable automatic cleanup (default: true)
    Store             BlacklistStore // Optional: custom store implementation
}
```

### DefaultBlacklistConfig

Returns a BlacklistConfig with sensible defaults.

```go
func DefaultBlacklistConfig() BlacklistConfig
```

---

## Processor Methods

### Token Creation

#### CreateToken

Creates a new access token with the given claims.

```go
func (p *Processor) CreateToken(claims Claims) (string, error)
```

**Parameters:**
- `claims` - Claims struct with user data

**Returns:**
- `string` - JWT token string
- `error` - Error if creation fails

**Example:**
```go
claims := jwt.Claims{
    UserID:   "user123",
    Username: "john_doe",
    Role:     "admin",
}
token, err := processor.CreateToken(claims)
```

#### CreateRefreshToken

Creates a new refresh token with the given claims.

```go
func (p *Processor) CreateRefreshToken(claims Claims) (string, error)
```

Uses `RefreshTokenTTL` for expiration instead of `AccessTokenTTL`.

#### CreateTokenWith

Creates a token with custom claims type.

```go
func (p *Processor) CreateTokenWith(claims CustomClaims) (string, error)
```

**Parameters:**
- `claims` - Must implement `CustomClaims` interface

**Example:**
```go
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

claims := &MyClaims{UserID: "123", TeamID: "team-abc"}
token, err := processor.CreateTokenWith(claims)
```

#### CreateRefreshTokenWith

Creates a refresh token with custom claims type.

```go
func (p *Processor) CreateRefreshTokenWith(claims CustomClaims) (string, error)
```

### Token Validation

#### ValidateToken

Validates a token and returns the claims.

```go
func (p *Processor) ValidateToken(tokenString string) (Claims, bool, error)
```

**Parameters:**
- `tokenString` - JWT token string

**Returns:**
- `Claims` - Parsed claims
- `bool` - True if token is valid
- `error` - Error if validation fails

**Example:**
```go
claims, valid, err := processor.ValidateToken(token)
if err != nil {
    switch {
    case errors.Is(err, jwt.ErrTokenExpired):
        // Handle expired token
    case errors.Is(err, jwt.ErrTokenRevoked):
        // Handle revoked token
    default:
        // Handle other errors
    }
    return
}
if !valid {
    // Token is invalid but no error
    return
}
// Token is valid, use claims
fmt.Println(claims.Username)
```

#### ValidateTokenWith

Validates a token with custom claims type.

```go
func (p *Processor) ValidateTokenWith(tokenString string, claims CustomClaims) (CustomClaims, bool, error)
```

**Example:**
```go
parsedClaims := &MyClaims{}
result, valid, err := processor.ValidateTokenWith(token, parsedClaims)
if valid {
    myClaims := result.(*MyClaims)
    fmt.Println(myClaims.TeamID)
}
```

#### ParseUnverified

Parses a token without verifying the signature.

```go
func ParseUnverified(tokenString string, claims any) (map[string]any, error)
```

**Warning:** Use only for debugging or when you need to inspect claims without verification.

**Example:**
```go
claims := &jwt.Claims{}
header, err := jwt.ParseUnverified(token, claims)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Algorithm: %s\n", header["alg"])
```

### Token Refresh

#### RefreshToken

Creates a new access token using a valid refresh token.

```go
func (p *Processor) RefreshToken(refreshTokenString string) (string, error)
```

**Parameters:**
- `refreshTokenString` - Valid refresh token

**Returns:**
- `string` - New access token
- `error` - Error if refresh fails

### Token Revocation

#### RevokeToken

Adds a token to the blacklist.

```go
func (p *Processor) RevokeToken(tokenString string) error
```

**Example:**
```go
err := processor.RevokeToken(token)
if err != nil {
    log.Printf("Revocation failed: %v", err)
}
```

#### IsTokenRevoked

Checks if a token has been revoked.

```go
func (p *Processor) IsTokenRevoked(tokenString string) (bool, error)
```

### Lifecycle

#### Close

Releases resources and securely clears sensitive data.

```go
func (p *Processor) Close() error
```

**Example:**
```go
processor, err := jwt.New(cfg)
if err != nil {
    log.Fatal(err)
}
defer processor.Close()
```

#### IsClosed

Checks if the processor has been closed.

```go
func (p *Processor) IsClosed() bool
```

---

## Claims Types

### Claims

Standard claims struct with common fields.

```go
type Claims struct {
    // Custom fields
    UserID      string         `json:"user_id,omitempty"`
    Username    string         `json:"username,omitempty"`
    Role        string         `json:"role,omitempty"`
    Permissions []string       `json:"permissions,omitempty"`
    Scopes      []string       `json:"scopes,omitempty"`
    Extra       map[string]any `json:"extra,omitempty"`
    SessionID   string         `json:"session_id,omitempty"`
    ClientID    string         `json:"client_id,omitempty"`

    // Standard JWT claims (embedded)
    RegisteredClaims
}
```

### RegisteredClaims

Standard JWT claims as defined in RFC 7519.

```go
type RegisteredClaims struct {
    Issuer    string      `json:"iss,omitempty"` // Token issuer
    Subject   string      `json:"sub,omitempty"` // Token subject
    Audience  []string    `json:"aud,omitempty"` // Intended audience
    ExpiresAt NumericDate `json:"exp"`           // Expiration time
    NotBefore NumericDate `json:"nbf"`           // Not valid before
    IssuedAt  NumericDate `json:"iat"`           // Issued at time
    ID        string      `json:"jti,omitempty"` // Unique token ID
}
```

### NumericDate

Represents a JSON numeric date (Unix timestamp).

```go
type NumericDate struct {
    time.Time
}

func NewNumericDate(t time.Time) NumericDate
```

### CustomClaims Interface

Interface for custom claims types.

```go
type CustomClaims interface {
    GetRegisteredClaims() *RegisteredClaims
    Validate() error
}
```

---

## Error Types

### Sentinel Errors

Use `errors.Is()` to check for specific error types.

```go
var (
    // Configuration errors
    ErrInvalidConfig        = errors.New("invalid configuration")
    ErrInvalidSecretKey     = errors.New("invalid secret key")
    ErrInvalidSigningMethod = errors.New("invalid signing method")

    // Token errors
    ErrInvalidToken       = errors.New("invalid token")
    ErrEmptyToken         = errors.New("empty token")
    ErrTokenRevoked       = errors.New("token revoked")
    ErrTokenMissingID     = errors.New("token missing ID")
    ErrTokenExpired       = errors.New("token expired")
    ErrTokenNotValidYet   = errors.New("token not valid yet")
    ErrTokenInvalidIssuer = errors.New("token invalid issuer")

    // Claims errors
    ErrInvalidClaims = errors.New("invalid claims")

    // Rate limiting errors
    ErrRateLimitExceeded = errors.New("rate limit exceeded")

    // Lifecycle errors
    ErrProcessorClosed = errors.New("processor closed")
    ErrStoreClosed     = errors.New("store closed")
)
```

### Error Handling Pattern

```go
claims, valid, err := processor.ValidateToken(token)
if err != nil {
    switch {
    case errors.Is(err, jwt.ErrTokenExpired):
        // Token has expired - prompt re-login
    case errors.Is(err, jwt.ErrTokenRevoked):
        // Token was revoked - force re-login
    case errors.Is(err, jwt.ErrTokenNotValidYet):
        // Token nbf is in the future - clock sync issue
    case errors.Is(err, jwt.ErrTokenInvalidIssuer):
        // Token issuer mismatch
    case errors.Is(err, jwt.ErrRateLimitExceeded):
        // Rate limit exceeded - retry later
    case errors.Is(err, jwt.ErrProcessorClosed):
        // Processor closed - fatal error
    default:
        // Other validation error
    }
    return
}
```

### ValidationError

Field-level validation failure with context.

```go
type ValidationError struct {
    Field   string
    Message string
    Err     error
}
```

### TokenError

Token-related error with additional context.

```go
type TokenError struct {
    Err       error
    TokenID   string
    ExpiresAt time.Time
}
```

### SigningError

Signing-related error.

```go
type SigningError struct {
    Algorithm string
    Err       error
}
```

---

## Interfaces

### Signer

Interface for custom signing algorithms.

```go
type Signer interface {
    Alg() string                              // Algorithm identifier
    Sign(data string) (string, error)         // Sign data
    Verify(data, signature string) error      // Verify signature
    Hash() crypto.Hash                        // Hash function
}
```

### RateLimitProvider

Interface for custom rate limiters.

```go
type RateLimitProvider interface {
    Allow(identifier string) bool  // Check if request is allowed
    Close()                        // Release resources
}
```

### BlacklistStore

Interface for custom blacklist storage.

```go
type BlacklistStore interface {
    Add(tokenID string, expiresAt time.Time) error
    Contains(tokenID string) (bool, error)
    Remove(tokenID string) error
    Clear() error
    Len() int
    Close() error
}
```

### ClockProvider

Interface for custom clock (testing).

```go
type ClockProvider interface {
    Now() time.Time
}
```

---

## Constants

### Signing Methods

```go
const (
    // HMAC signing methods (symmetric)
    SigningMethodHS256 SigningMethod = "HS256"
    SigningMethodHS384 SigningMethod = "HS384"
    SigningMethodHS512 SigningMethod = "HS512"

    // RSA signing methods (asymmetric)
    SigningMethodRS256 SigningMethod = "RS256"
    SigningMethodRS384 SigningMethod = "RS384"
    SigningMethodRS512 SigningMethod = "RS512"

    // ECDSA signing methods (asymmetric)
    SigningMethodES256 SigningMethod = "ES256"
    SigningMethodES384 SigningMethod = "ES384"
    SigningMethodES512 SigningMethod = "ES512"
)
```

### Validation Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `maxStringLength` | 256 | Maximum string field length |
| `maxArraySize` | 100 | Maximum array size |
| `maxExtraSize` | 50 | Maximum extra claims fields |
| `MaxTokenSize` | 8192 | Maximum token size in bytes |

---

## Helper Functions

### NewNumericDate

Creates a NumericDate from time.Time.

```go
func NewNumericDate(t time.Time) NumericDate
```

### DefaultBlacklistConfig

Returns default blacklist configuration.

```go
func DefaultBlacklistConfig() BlacklistConfig
```

### NewRateLimiter

Creates a new rate limiter with the specified parameters.

```go
func NewRateLimiter(rate int, window time.Duration) *RateLimiter
```

---

## Type Assertions

### Checking Algorithm Type

```go
switch cfg.SigningMethod {
case jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512:
    // HMAC - symmetric key
    cfg.SecretKey = "your-secret-key"
case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512:
    // RSA - asymmetric key
    cfg.SigningKey = rsaPrivateKey
case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
    // ECDSA - asymmetric key
    cfg.SigningKey = ecdsaPrivateKey
}
```

---
