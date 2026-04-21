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
func New(cfg Config) (*Processor, error)

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
    VerificationKey any           // Optional: public key for verification only (*rsa.PublicKey or *ecdsa.PublicKey)
    SigningMethod   SigningMethod // HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512

    // Token configuration
    AccessTokenTTL    time.Duration // Default: 15 minutes (supports YAML/JSON: access_token_ttl)
    RefreshTokenTTL   time.Duration // Default: 7 days (supports YAML/JSON: refresh_token_ttl)
    Issuer            string        // Default: "jwt-service" (supports YAML/JSON: issuer)
    ExpectedAudience  string        // Optional: reject tokens without matching aud claim (supports YAML/JSON: expected_audience)

    // Blacklist configuration (embedded)
    Blacklist BlacklistConfig // Supports YAML/JSON: blacklist

    // Rate limiting
    EnableRateLimit bool              // Default: false (supports YAML/JSON: enable_rate_limit)
    RateLimitRate   int               // Default: 100 (supports YAML/JSON: rate_limit_rate)
    RateLimitWindow time.Duration     // Default: 1 minute (supports YAML/JSON: rate_limit_window)
    RateLimiter     RateLimitProvider // Optional: custom rate limiter (not serialized)

    // Clock provider for time operations (optional, defaults to SystemClock)
    Clock ClockProvider // Optional: inject custom clock for testing (not serialized)
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
    CleanupInterval   time.Duration  // Cleanup interval (default: 5 minutes)
    MaxSize           int            // Maximum entries (default: 100000)
    EnableAutoCleanup bool           // Enable automatic cleanup (default: true)
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

#### Create

Creates a new access token with the given claims.
Accepts any type implementing `CustomClaims`, including `*Claims` for built-in claims.

```go
func (p *Processor) Create(claims CustomClaims) (string, error)
```

**Parameters:**
- `claims` - Any type implementing `CustomClaims` (use `&Claims{}` for built-in claims)

**Returns:**
- `string` - JWT token string
- `error` - Error if creation fails

**Example (built-in Claims):**
```go
claims := &jwt.Claims{
    UserID:   "user123",
    Username: "john_doe",
    Role:     "admin",
}
token, err := processor.Create(claims)
```

**Example (custom claims):**
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
token, err := processor.Create(claims)
```

#### CreateRefresh

Creates a new refresh token with the given claims.
Accepts any type implementing `CustomClaims`, including `*Claims` for built-in claims.

```go
func (p *Processor) CreateRefresh(claims CustomClaims) (string, error)
```

Uses `RefreshTokenTTL` for expiration instead of `AccessTokenTTL`.

### Token Validation

#### Validate

Validates a token and returns the claims.

```go
func (p *Processor) Validate(tokenString string) (Claims, bool, error)
```

**Parameters:**
- `tokenString` - JWT token string

**Returns:**
- `Claims` - Parsed claims (value copy)
- `bool` - True if token is valid
- `error` - Error if validation fails

**Example:**
```go
claims, valid, err := processor.Validate(token)
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

#### ValidateInto

Validates a token and populates the provided custom claims.

```go
func (p *Processor) ValidateInto(tokenString string, claims CustomClaims) (CustomClaims, bool, error)
```

**Parameters:**
- `tokenString` - JWT token string
- `claims` - Must be a pointer to a type implementing `CustomClaims`. Populated in place.

**Returns:**
- `CustomClaims` - The same claims pointer on success
- `bool` - True if token is valid
- `error` - Error if validation fails

**Example:**
```go
parsedClaims := &MyClaims{}
result, valid, err := processor.ValidateInto(token, parsedClaims)
if valid {
    myClaims := result.(*MyClaims)
    fmt.Println(myClaims.TeamID)
}
```

#### ParseUnverified

Parses a token without verifying the signature. This is a method on `*Processor`.

```go
func (p *Processor) ParseUnverified(tokenString string, claims any) error
```

**Warning:** Use only for debugging or when you need to inspect claims without verification.
The returned claims are NOT validated and should NOT be trusted.

**Example:**
```go
var parsedClaims jwt.Claims
err := processor.ParseUnverified(token, &parsedClaims)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("UserID: %s\n", parsedClaims.UserID)
```

### Token Refresh

#### Refresh

Creates a new access token using a valid refresh token.

```go
func (p *Processor) Refresh(refreshTokenString string) (string, error)
```

**Parameters:**
- `refreshTokenString` - Valid refresh token

**Returns:**
- `string` - New access token
- `error` - Error if refresh fails

#### RefreshInto

Refreshes a custom-claims refresh token into a new access token.

```go
func (p *Processor) RefreshInto(refreshTokenString string, claims CustomClaims) (string, error)
```

**Parameters:**
- `refreshTokenString` - Valid refresh token
- `claims` - Must be a pointer to a type implementing `CustomClaims`

**Returns:**
- `string` - New access token
- `error` - Error if refresh fails

### Token Revocation

#### Revoke

Adds a token to the blacklist.

```go
func (p *Processor) Revoke(tokenString string) error
```

**Example:**
```go
err := processor.Revoke(token)
if err != nil {
    log.Printf("Revocation failed: %v", err)
}
```

#### IsRevoked

Checks if a token has been revoked.

```go
func (p *Processor) IsRevoked(tokenString string) (bool, error)
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
    Issuer    string        `json:"iss,omitempty"` // Token issuer
    Subject   string        `json:"sub,omitempty"` // Token subject
    Audience  StringOrSlice `json:"aud,omitempty"` // Intended audience (string or []string per RFC 7519 §4.1.3)
    ExpiresAt NumericDate   `json:"exp"`           // Expiration time
    NotBefore NumericDate   `json:"nbf"`           // Not valid before
    IssuedAt  NumericDate   `json:"iat"`           // Issued at time
    ID        string        `json:"jti,omitempty"` // Unique token ID
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

### RateLimitKeyer Interface

Optional interface for custom claims types to provide a rate limit key.

```go
type RateLimitKeyer interface {
    RateLimitKey() string
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
    ErrAlgorithmMismatch  = errors.New("token algorithm does not match configured signing method")
    ErrTokenRevoked       = errors.New("token revoked")
    ErrTokenMissingID     = errors.New("token missing ID")
    ErrTokenExpired       = errors.New("token expired")
    ErrTokenNotValidYet   = errors.New("token not valid yet")
    ErrTokenInvalidIssuer   = errors.New("token invalid issuer")
    ErrTokenInvalidAudience = errors.New("token invalid audience")

    // Claims errors
    ErrInvalidClaims = errors.New("invalid claims")

    // Rate limiting errors
    ErrRateLimitExceeded = errors.New("rate limit exceeded")

    // Blacklist errors
    ErrBlacklistNotConfigured = errors.New("blacklist not configured")

    // Lifecycle errors
    ErrProcessorClosed = errors.New("processor closed")
    ErrStoreClosed     = errors.New("store closed")
)
```

### Error Handling Pattern

```go
claims, valid, err := processor.Validate(token)
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
    case errors.Is(err, jwt.ErrTokenInvalidAudience):
        // Token audience mismatch
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

---

## Interfaces

### TokenManager

The primary interface for JWT token operations. All methods must be safe for concurrent use.

```go
type TokenManager interface {
    // Token operations (accept CustomClaims — use &Claims{} for built-in)
    Create(claims CustomClaims) (string, error)
    Validate(tokenString string) (Claims, bool, error)
    CreateRefresh(claims CustomClaims) (string, error)
    Refresh(refreshTokenString string) (string, error)

    // Custom claims target operations
    ValidateInto(tokenString string, claims CustomClaims) (CustomClaims, bool, error)
    RefreshInto(refreshTokenString string, claims CustomClaims) (string, error)

    // Common operations
    Revoke(tokenString string) error
    IsRevoked(tokenString string) (bool, error)
    ParseUnverified(tokenString string, claims any) error
    Close() error
    IsClosed() bool
}
```

### RateLimitProvider

Interface for custom rate limiters. Implementations must be safe for concurrent use.

```go
type RateLimitProvider interface {
    Allow(key string) bool       // Check if a single request is allowed
    AllowN(key string, n int) bool // Check if n requests are allowed
    Reset(key string)            // Remove rate limit state for a key
    Close()                      // Release resources
}
```

### BlacklistStore

Interface for custom blacklist storage backends.

```go
type BlacklistStore interface {
    Add(tokenID string, expiresAt time.Time) error
    Contains(tokenID string) (bool, error)
    Close() error
}
```

### ClockProvider

Interface for custom clock (testing).

```go
type ClockProvider interface {
    Now() time.Time
}

// Built-in implementations:
type SystemClock struct{} // Uses time.Now()
type FixedClock struct { T time.Time } // Returns fixed time
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

    // RSA signing methods (asymmetric, PKCS#1 v1.5)
    SigningMethodRS256 SigningMethod = "RS256"
    SigningMethodRS384 SigningMethod = "RS384"
    SigningMethodRS512 SigningMethod = "RS512"

    // RSA-PSS signing methods (asymmetric, recommended over PKCS#1 v1.5)
    SigningMethodPS256 SigningMethod = "PS256"
    SigningMethodPS384 SigningMethod = "PS384"
    SigningMethodPS512 SigningMethod = "PS512"

    // ECDSA signing methods (asymmetric)
    SigningMethodES256 SigningMethod = "ES256"
    SigningMethodES384 SigningMethod = "ES384"
    SigningMethodES512 SigningMethod = "ES512"
)
```

### Validation Limits

The following limits are enforced internally (not exported):

| Limit | Value | Description |
|-------|-------|-------------|
| String field max length | 256 | Maximum length for string fields |
| Array max size | 100 | Maximum elements in arrays |
| Extra claims max fields | 50 | Maximum keys in Extra map |
| Token max size | 8192 | Maximum token size in bytes |
| Segment max length | 4096 | Maximum base64 segment size (internal: `maxSegmentLength`) |

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
func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter
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
