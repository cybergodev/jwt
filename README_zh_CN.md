# JWT 库 - 高性能 Go JWT 解决方案

[![Go 版本](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/cybergodev/jwt.svg)](https://pkg.go.dev/github.com/cybergodev/jwt)
[![许可证](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![安全性](https://img.shields.io/badge/Security-Production%20Ready-green.svg)](docs/SECURITY.md)
[![线程安全](https://img.shields.io/badge/thread%20safe-yes-brightgreen.svg)](https://github.com/cybergodev/jwt)

一个**生产就绪的 Go JWT 库**，专注于安全性、性能和易用性。提供清晰的结构化配置 API，内置令牌撤销和速率限制功能。

**[📖 English Documentation](README.md)**

---

## 核心特性

- **精简 API** - 用最少的代码创建、验证和撤销令牌
- **安全优先** - 输入验证、速率限制、令牌撤销和安全密钥处理
- **性能优化** - 对象池和高效内存管理
- **零依赖** - 完全基于 Go 标准库构建
- **生产就绪** - 线程安全操作、可配置黑名单和全面的错误处理
- **多种算法** - 支持 HMAC、RSA 和 ECDSA 签名方法

## 安装

需要 **Go 1.25** 或更高版本。

```bash
go get github.com/cybergodev/jwt
```

## 快速开始

### 最简配置（HMAC）

使用库最简单的方式 - 从 `DefaultConfig()` 开始：

```go
package main

import (
    "fmt"
    "log"

    "github.com/cybergodev/jwt"
)

func main() {
    // 从 DefaultConfig() 开始获取合理的默认值
    // 然后只自定义需要的字段
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~"

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    // 创建用户声明
    claims := jwt.Claims{
        UserID:      "user123",
        Username:    "john_doe",
        Role:        "admin",
        SessionID:   "session_12345",
        Permissions: []string{"read", "write"},
    }

    // 创建令牌（传指针 - Claims 通过指针接收者实现 CustomClaims 接口）
    token, err := processor.Create(&claims)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("令牌:", token)

    // 验证令牌
    parsedClaims, valid, err := processor.Validate(token)
    if err != nil {
        log.Fatal(err)
    }
    if !valid {
        log.Fatal("令牌无效")
    }
    fmt.Printf("用户: %s, 角色: %s\n", parsedClaims.Username, parsedClaims.Role)

    // 撤销令牌（添加到黑名单）
    err = processor.Revoke(token)
    if err != nil {
        log.Printf("撤销失败: %v", err)
    }
}
```

### 完整配置（推荐生产环境使用）

需要完全配置控制的应用：

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/cybergodev/jwt"
)

func main() {
    // 使用 DefaultConfig() 作为起点
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~"
    cfg.AccessTokenTTL = 15 * time.Minute
    cfg.RefreshTokenTTL = 7 * 24 * time.Hour
    cfg.Issuer = "my-app"
    cfg.SigningMethod = jwt.SigningMethodHS512

    // 可选：启用速率限制
    cfg.EnableRateLimit = true
    cfg.RateLimitRate = 100
    cfg.RateLimitWindow = time.Minute

    // 可选：配置黑名单
    cfg.Blacklist = jwt.BlacklistConfig{
        MaxSize:           100000,
        CleanupInterval:   5 * time.Minute,
        EnableAutoCleanup: true,
    }

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
    }

    // 创建访问令牌（传指针）
    accessToken, err := processor.Create(&claims)
    if err != nil {
        log.Fatal(err)
    }

    // 创建刷新令牌（更长的 TTL）
    refreshToken, err := processor.CreateRefresh(&claims)
    if err != nil {
        log.Fatal(err)
    }

    // 验证令牌
    parsedClaims, valid, err := processor.Validate(accessToken)
    if err != nil || !valid {
        log.Fatal("令牌无效")
    }
    fmt.Printf("用户: %s\n", parsedClaims.Username)

    // 使用刷新令牌获取新的访问令牌
    newAccessToken, err := processor.Refresh(refreshToken)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("新访问令牌:", newAccessToken[:50]+"...")

    // 撤销令牌
    err = processor.Revoke(accessToken)
    if err != nil {
        log.Printf("撤销失败: %v", err)
    }

    // 检查令牌是否已撤销
    isRevoked, err := processor.IsRevoked(accessToken)
    if err != nil {
        log.Printf("检查失败: %v", err)
    }
    fmt.Printf("令牌已撤销: %v\n", isRevoked)
}
```

### 非对称签名（RSA/ECDSA）

适用于需要公钥/私钥分离的分布式系统：

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "fmt"
    "log"

    "github.com/cybergodev/jwt"
)

func main() {
    // 生成 RSA 密钥对（生产环境请使用 2048+ 位密钥）
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal(err)
    }

    // 使用 RSA 私钥创建处理器
    cfg := jwt.DefaultConfig()
    cfg.SigningKey = privateKey           // *rsa.PrivateKey 或 *ecdsa.PrivateKey
    cfg.SigningMethod = jwt.SigningMethodRS256
    cfg.Issuer = "my-secure-service"

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
    }

    token, err := processor.Create(&claims)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("RSA 令牌:", token[:50]+"...")

    // 验证令牌
    parsedClaims, valid, err := processor.Validate(token)
    if err != nil || !valid {
        log.Fatal("令牌无效")
    }
    fmt.Printf("用户: %s\n", parsedClaims.Username)
}
```

使用 ECDSA 时，替换密钥生成和方法：

```go
import "crypto/ecdsa"
import "crypto/elliptic"

privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
cfg.SigningKey = privateKey
cfg.SigningMethod = jwt.SigningMethodES256
```

> **VerificationKey**：对于仅验证的服务，可将 `cfg.VerificationKey` 设置为公钥。设置后，验证使用 `VerificationKey` 而非从 `SigningKey` 派生公钥。完整示例参见 [非对称签名示例](examples/5_asymmetric.go)。

### 自定义声明类型

使用自定义声明类型以获得更强的类型安全性：

```go
package main

import (
    "errors"
    "fmt"
    "log"

    "github.com/cybergodev/jwt"
)

// 自定义声明类型
type MyClaims struct {
    UserID string   `json:"user_id"`
    TeamID string   `json:"team_id"`
    Roles  []string `json:"roles,omitempty"`
    jwt.RegisteredClaims
}

// GetRegisteredClaims 实现 jwt.CustomClaims 接口
func (c *MyClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
    return &c.RegisteredClaims
}

// Validate 实现 jwt.CustomClaims 接口
func (c *MyClaims) Validate() error {
    if c.UserID == "" {
        return errors.New("user_id is required")
    }
    return nil
}

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-super-secret-key-at-least-32-bytes-long!"

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    // 使用自定义声明创建令牌
    claims := &MyClaims{
        UserID: "user123",
        TeamID: "team-abc",
        Roles:  []string{"admin", "developer"},
    }

    token, err := processor.Create(claims)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("令牌:", token[:50]+"...")

    // 使用自定义声明验证令牌
    parsedClaims := &MyClaims{}
    result, valid, err := processor.ValidateInto(token, parsedClaims)
    if err != nil || !valid {
        log.Fatal("令牌无效")
    }
    fmt.Printf("用户ID: %s, 团队ID: %s\n", result.(*MyClaims).UserID, result.(*MyClaims).TeamID)
}
```

## 配置

### 配置选项

```go
cfg := jwt.DefaultConfig()

// === 签名配置（选择其一）===
cfg.SecretKey = "your-32-byte-secret-key-here............."  // 用于 HMAC 算法
cfg.SigningKey = privateKey                                  // 用于 RSA/ECDSA (*rsa.PrivateKey 或 *ecdsa.PrivateKey)
cfg.VerificationKey = publicKey                              // 可选：仅用于验证的公钥
cfg.SigningMethod = jwt.SigningMethodHS256                   // 见下表

// === 令牌设置 ===
cfg.AccessTokenTTL = 15 * time.Minute
cfg.RefreshTokenTTL = 7 * 24 * time.Hour
cfg.Issuer = "my-app"
cfg.ExpectedAudience = "my-api"                              // 可选：拒绝不匹配 aud 的令牌

// === 黑名单设置（嵌入在 Config 中）===
cfg.Blacklist = jwt.BlacklistConfig{
    MaxSize:           100000,        // 默认：100000
    CleanupInterval:   5 * time.Minute,  // 默认：5 * time.Minute
    EnableAutoCleanup: true,          // 默认：true
    Store:             nil,           // 可选：自定义 BlacklistStore 实现
}

// === 速率限制 ===
cfg.EnableRateLimit = true
cfg.RateLimitRate = 100            // 每个窗口最大请求数（默认：100）
cfg.RateLimitWindow = time.Minute  // 每用户速率限制窗口（默认：1 * time.Minute）
cfg.RateLimiter = nil              // 可选：自定义 RateLimitProvider 实现

// === 时钟提供器（可选，用于测试）===
cfg.Clock = jwt.FixedClock{T: time.Now()}  // 默认使用 SystemClock

processor, err := jwt.New(cfg)
if err != nil {
    log.Fatal(err)
}
defer processor.Close()
```

### 支持的签名方法

| 方法 | 类型 | 描述 |
|------|------|------|
| `SigningMethodHS256` | HMAC | SHA-256（默认，推荐 HMAC） |
| `SigningMethodHS384` | HMAC | SHA-384 |
| `SigningMethodHS512` | HMAC | SHA-512 |
| `SigningMethodRS256` | RSA | SHA-256（2048+ 位密钥） |
| `SigningMethodRS384` | RSA | SHA-384 |
| `SigningMethodRS512` | RSA | SHA-512 |
| `SigningMethodES256` | ECDSA | SHA-256（P-256 曲线） |
| `SigningMethodES384` | ECDSA | SHA-384（P-384 曲线） |
| `SigningMethodES512` | ECDSA | SHA-512（P-521 曲线） |

## 声明结构

### 内置声明

```go
claims := jwt.Claims{
    // 自定义字段
    UserID:      "user123",
    Username:    "john_doe",
    Role:        "admin",
    Permissions: []string{"read", "write"},
    Scopes:      []string{"api:read", "api:write"},
    SessionID:   "sess-abc123",
    ClientID:    "client-xyz789",

    // 额外字段（任意附加数据）
    Extra: map[string]any{
        "department": "engineering",
        "location":   "us-west",
    },

    // 标准 JWT 声明（嵌入 RegisteredClaims）
    // Issuer, Subject, Audience, ExpiresAt, NotBefore, IssuedAt, ID
}
```

> **Extra 字段限制**：`Extra` map 中的值仅支持 `string` 和 `[]string` 类型。嵌套 map 和其他类型在验证时会被拒绝。每个 map 最多 50 个键。

### 注册声明（标准 JWT）

| 字段 | JSON 键 | 描述 |
|------|---------|------|
| `Issuer` | `iss` | 令牌颁发者 |
| `Subject` | `sub` | 令牌主题 |
| `Audience` | `aud` | 目标受众（接受字符串或数组） |
| `ExpiresAt` | `exp` | 过期时间 |
| `NotBefore` | `nbf` | 生效时间 |
| `IssuedAt` | `iat` | 颁发时间 |
| `ID` | `jti` | 唯一令牌 ID |

## HTTP 服务器集成

### Gin 框架

```go
func JWTMiddleware(processor *jwt.Processor) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        token = strings.TrimPrefix(token, "Bearer ")

        claims, valid, err := processor.Validate(token)
        if err != nil || !valid {
            c.JSON(401, gin.H{"error": "无效令牌"})
            c.Abort()
            return
        }

        c.Set("user", claims)
        c.Next()
    }
}
```

### 标准库

```go
func loginHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims := jwt.Claims{
            UserID:   "user123",
            Username: "john_doe",
            Role:     "admin",
        }

        token, err := processor.Create(&claims)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        json.NewEncoder(w).Encode(map[string]string{
            "access_token": token,
            "token_type":   "Bearer",
        })
    }
}

func protectedHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")

        claims, valid, err := processor.Validate(tokenString)
        if err != nil || !valid {
            http.Error(w, "无效令牌", http.StatusUnauthorized)
            return
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "message": "访问已授权",
            "user":    claims.Username,
            "role":    claims.Role,
        })
    }
}
```

## 安全特性

### 输入验证
- **密钥要求**：最少 32 字节，带熵验证
- **声明验证**：字符串长度限制、数组大小限制、控制字符过滤
- **模式检测**：阻止可疑模式（XSS、SQL 注入、路径遍历）
- **大小限制**：每个字符串字段最多 256 字节，每个数组 100 项，Extra 最多 50 个键

### 令牌安全
- **算法验证**：严格的签名方法验证（防止算法混淆攻击）
- **令牌撤销**：支持可配置清理的黑名单
- **过期强制**：自动验证 `exp`、`nbf` 和 `iat` 声明
- **颁发者/受众验证**：可选的颁发者和受众声明验证

### 运营安全
- **速率限制**：令牌桶算法，每用户限制
- **线程安全**：所有操作都支持 goroutine 安全
- **安全清理**：处理器关闭时密钥清零
- **资源限制**：可配置的黑名单大小

## 错误处理

### 错误检查模式

```go
claims, valid, err := processor.Validate(token)
if err != nil {
    switch {
    case errors.Is(err, jwt.ErrTokenExpired):
        // 令牌已过期
    case errors.Is(err, jwt.ErrTokenRevoked):
        // 令牌已被撤销
    case errors.Is(err, jwt.ErrInvalidToken):
        // 令牌格式错误或签名无效
    case errors.Is(err, jwt.ErrRateLimitExceeded):
        // 超过速率限制
    case errors.Is(err, jwt.ErrTokenNotValidYet):
        // 令牌 nbf 声明在未来
    case errors.Is(err, jwt.ErrTokenInvalidIssuer):
        // 令牌颁发者不匹配
    case errors.Is(err, jwt.ErrTokenInvalidAudience):
        // 令牌受众不匹配
    case errors.Is(err, jwt.ErrInvalidClaims):
        // 声明验证失败
    default:
        // 其他错误
    }
}
```

### 可用错误

| 错误 | 描述 |
|------|------|
| `ErrInvalidConfig` | 配置验证失败 |
| `ErrInvalidSecretKey` | 密钥太短或太弱 |
| `ErrInvalidSigningMethod` | 不支持的签名方法 |
| `ErrInvalidToken` | 令牌格式错误或签名无效 |
| `ErrEmptyToken` | 提供了空令牌字符串 |
| `ErrTokenRevoked` | 令牌存在于黑名单中 |
| `ErrTokenExpired` | 令牌已过期 |
| `ErrTokenNotValidYet` | 令牌 nbf 声明在未来 |
| `ErrTokenInvalidIssuer` | 令牌颁发者不匹配 |
| `ErrTokenInvalidAudience` | 令牌受众不匹配 |
| `ErrTokenMissingID` | 令牌缺少 jti 声明 |
| `ErrInvalidClaims` | 声明验证失败 |
| `ErrRateLimitExceeded` | 超过速率限制 |
| `ErrBlacklistNotConfigured` | 黑名单未配置 |
| `ErrProcessorClosed` | 处理器已关闭 |
| `ErrStoreClosed` | 存储已关闭 |

### 结构化错误类型

对于需要编程访问错误详情的应用：

```go
// ValidationError - 字段级验证失败（来自声明深度验证）
var verr *jwt.ValidationError
if errors.As(err, &verr) {
    fmt.Println("字段:", verr.Field, "问题:", verr.Message)
}

// TokenError - 带上下文的令牌相关错误
var terr *jwt.TokenError
if errors.As(err, &terr) {
    fmt.Println("令牌 ID:", terr.TokenID, "过期时间:", terr.ExpiresAt)
}
```

## API 参考

### 创建处理器

```go
// 最简 - 使用默认配置
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key"
processor, err := jwt.New(cfg)

// 完整配置
cfg := jwt.DefaultConfig()
cfg.SecretKey = "your-secret-key"
cfg.Issuer = "my-app"
cfg.SigningMethod = jwt.SigningMethodHS512
processor, err := jwt.New(cfg)
```

### Processor 方法

| 方法 | 描述 |
|------|------|
| `Create(claims CustomClaims) (string, error)` | 创建访问令牌 |
| `Validate(token string) (Claims, bool, error)` | 验证令牌并返回内置 Claims |
| `CreateRefresh(claims CustomClaims) (string, error)` | 创建刷新令牌 |
| `Refresh(refreshToken string) (string, error)` | 刷新访问令牌 |
| `ValidateInto(token string, claims CustomClaims) (CustomClaims, bool, error)` | 使用自定义声明类型验证 |
| `RefreshInto(refreshToken string, claims CustomClaims) (string, error)` | 使用自定义声明类型刷新 |
| `Revoke(token string) error` | 添加令牌到黑名单 |
| `IsRevoked(token string) (bool, error)` | 检查令牌是否已撤销 |
| `ParseUnverified(token string, claims any) error` | 解析令牌但不验证签名 |
| `Close() error` | 释放资源 |
| `IsClosed() bool` | 检查处理器是否已关闭 |

### CustomClaims 接口

```go
type CustomClaims interface {
    GetRegisteredClaims() *RegisteredClaims
    Validate() error
}
```

`*Claims` 自动实现 `CustomClaims` 接口。向接受 `CustomClaims` 的方法传参时使用 `&claims`。

### 可选接口

自定义声明类型可实现 `RateLimitKeyer`，在 `Subject` 为空时提供速率限制键：

```go
type RateLimitKeyer interface {
    RateLimitKey() string
}
```

### 可扩展接口

| 接口 | 用途 |
|------|------|
| `TokenManager` | 核心令牌操作（由 `*Processor` 实现） |
| `BlacklistStore` | 自定义黑名单存储后端（如 Redis） |
| `RateLimitProvider` | 自定义速率限制实现 |
| `ClockProvider` | 时间注入（测试时使用 `SystemClock` 或 `FixedClock`） |

#### 自定义黑名单存储示例

```go
// 为 Redis 或其他后端实现 BlacklistStore
type RedisStore struct {
    client *redis.Client
}

func (s *RedisStore) Add(tokenID string, expiresAt time.Time) error {
    return s.client.Set(ctx, "blacklist:"+tokenID, "1", time.Until(expiresAt)).Err()
}

func (s *RedisStore) Contains(tokenID string) (bool, error) {
    return s.client.Exists(ctx, "blacklist:"+tokenID).Result()
}

func (s *RedisStore) Close() error {
    return s.client.Close()
}

// 在配置中使用
cfg.Blacklist = jwt.BlacklistConfig{
    Store: &RedisStore{client: rdb},
}
```

## 辅助类型与函数

| 符号 | 描述 |
|------|------|
| `NumericDate` | JSON 数值日期（Unix 时间戳），用于 JWT 时间声明 |
| `NewNumericDate(t time.Time) NumericDate` | 从 time.Time 创建 NumericDate |
| `StringOrSlice` | 受众声明类型 — 符合 RFC 7519，接受字符串或数组 |
| `RateLimiter` | 内置令牌桶速率限制器（实现 `RateLimitProvider`） |
| `NewRateLimiter(maxRate int, window time.Duration) *RateLimiter` | 创建新的速率限制器 |
| `DefaultBlacklistConfig() BlacklistConfig` | 返回具有合理默认值的黑名单配置 |

```go
// NumericDate 用于 JWT 时间声明
expiresAt := jwt.NewNumericDate(time.Now().Add(time.Hour))

// StringOrSlice 用于受众声明
claims.Audience = jwt.StringOrSlice{"api-v1", "api-v2"}

// 独立速率限制器
rl := jwt.NewRateLimiter(100, time.Minute)
rl.Allow("user:123")  // true/false
rl.Close()

// 默认黑名单配置
blCfg := jwt.DefaultBlacklistConfig()
// MaxSize: 100000, CleanupInterval: 5 * time.Minute, EnableAutoCleanup: true
```

## 详细文档

| 文档 | 内容 | 使用场景 |
|------|------|----------|
| [API 参考](docs/API.md) | 完整 API 文档 | 开发参考 |
| [安全指南](docs/SECURITY.md) | 安全特性说明 | 安全审计 |
| [性能指南](docs/PERFORMANCE.md) | 性能优化技巧 | 高并发场景 |
| [集成示例](docs/EXAMPLES.md) | 框架集成代码 | 项目集成 |
| [最佳实践](docs/BEST_PRACTICES.md) | 生产环境指南 | 部署 |
| [故障排除](docs/TROUBLESHOOTING.md) | 常见问题解决方案 | 问题诊断 |
| [并发指南](docs/CONCURRENCY.md) | 线程安全和模式 | 并发应用 |

## 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

---

如果这个项目对您有帮助，请给它一个 Star！
