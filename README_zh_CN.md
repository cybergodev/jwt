# JWT库 - 高性能 Go JWT 解决方案

[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/cybergodev/jwt.svg)](https://pkg.go.dev/github.com/cybergodev/jwt)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Production%20Ready-green.svg)](docs/SECURITY.md)
[![Thread Safe](https://img.shields.io/badge/thread%20safe-yes-brightgreen.svg)](https://github.com/cybergodev/json)

**生产就绪的 Go JWT 库**，专注于安全性、性能和易用性。提供简单的便捷函数和高级处理器模式，支持灵活的 JWT 操作、内置令牌撤销和速率限制。

### **[📖 English Docs](README.md)** - User guide

---

## 🎯 核心特性

- ⚡ **极简API** - 仅需3个便捷函数：`CreateToken`、`ValidateToken`、`RevokeToken`
- 🛡️ **安全为先** - 输入验证、速率限制、令牌撤销和安全密钥处理
- 🚀 **性能优化** - 对象池、处理器缓存和高效内存管理
- 📦 **零依赖** - 完全基于 Go 标准库构建
- 🔧 **生产就绪** - 线程安全操作、可配置黑名单和全面错误处理
- 🌟 **灵活架构** - 简单便捷API或带速率限制的高级处理器模式

## 📦 安装

```bash
go get github.com/cybergodev/jwt
```

## ⚡ 5分钟快速上手

### 1️⃣ 创建Token
```go
package main

import (
    "fmt"
    "time"

    "github.com/cybergodev/jwt"
)

func main() {
    // 设置密钥（生产环境建议使用环境变量）
    secretKey := "your-super-secret-key-at-least-32-bytes-long!"

    // 创建用户声明
    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
        Permissions: []string{"read", "write"},
    }

    // 设置Token过期时间 (本例中设置为2小时)
    claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Hour))

    // 创建token - 就这么简单！
    token, err := jwt.CreateToken(secretKey, claims)
    if err != nil {
        panic(err)
    }

    fmt.Println("Token:", token)
}
```

### 2️⃣ 验证Token
```go
// 验证token
claims, valid, err := jwt.ValidateToken(secretKey, token)
if err != nil {
    fmt.Printf("验证失败: %v\n", err)
    return
}

if !valid {
    fmt.Println("Token 无效")
    return
}

fmt.Printf("用户: %s, 角色: %s\n", claims.Username, claims.Role)
```

### 3️⃣ 撤销 Token
```go
// 撤销 token（加入黑名单）
err = jwt.RevokeToken(secretKey, token)
if err != nil {
    fmt.Printf("撤销失败: %v\n", err)
}
```

## 🏗️ 高级用法

### 处理器模式（推荐用于生产环境）
处理器模式提供更好的资源管理、自定义配置和可选的速率限制。

```go
// 使用默认配置创建处理器
processor, err := jwt.New(secretKey)
if err != nil {
    panic(err)
}
defer processor.Close() // 始终关闭以释放资源

// 创建访问令牌
token, err := processor.CreateToken(claims)

// 验证令牌
claims, valid, err := processor.ValidateToken(token)

// 撤销令牌（加入黑名单）
err = processor.RevokeToken(token)

// 检查令牌是否已被撤销
isRevoked, err := processor.IsTokenRevoked(token)

// 创建刷新令牌（更长的有效期）
refreshToken, err := processor.CreateRefreshToken(claims)

// 使用刷新令牌获取新的访问令牌
newToken, err := processor.RefreshToken(refreshToken)

// 使用自定义黑名单配置创建处理器
blacklistConfig := jwt.DefaultBlacklistConfig()
processor, err = jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

### 自定义配置
```go
// 配置令牌有效期和签名方法
config := jwt.Config{
    AccessTokenTTL:  15 * time.Minute,       // 短期访问令牌
    RefreshTokenTTL: 7 * 24 * time.Hour,     // 长期刷新令牌
    Issuer:          "your-app",             // 令牌签发者标识
    SigningMethod:   jwt.SigningMethodHS256, // HS256、HS384 或 HS512
}

// 配置黑名单行为
blacklistConfig := jwt.BlacklistConfig{
    MaxSize:           10000,             // 黑名单最大令牌数量
    CleanupInterval:   5 * time.Minute,   // 清理过期条目的频率
    EnableAutoCleanup: true,              // 自动删除过期令牌
}

// 使用两种配置创建处理器
processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
if err != nil {
    panic(err)
}
defer processor.Close()
```

## 🌟 架构概览

| 组件                | 说明                                  | 使用场景                    |
|---------------------|---------------------------------------|----------------------------|
| 🎯 **便捷函数**     | 简单的3函数API，内置缓存              | 快速原型开发、简单应用      |
| 🔧 **处理器模式**   | 可配置、资源管理的JWT操作             | 生产应用、自定义需求        |
| 🛡️ **安全特性**     | 输入验证、速率限制、令牌黑名单        | 防护常见JWT攻击             |
| ⚡ **性能优化**      | 对象池、处理器缓存                    | 高吞吐量应用                |
| 📦 **零依赖**       | 仅使用标准库                          | 最小攻击面、易于审计        |

## 🎛️ 速率限制

本库通过处理器模式提供灵活的速率限制：

### 便捷函数（无速率限制）
便捷函数（`CreateToken`、`ValidateToken`、`RevokeToken`）使用内部处理器缓存，不强制执行速率限制。适用于：
- 内部服务
- 可信环境
- 开发和测试

```go
// 不应用速率限制
token, err := jwt.CreateToken(secretKey, claims)
claims, valid, err := jwt.ValidateToken(secretKey, token)
err = jwt.RevokeToken(secretKey, token)
```

### 带速率限制的处理器
为面向公众的API启用速率限制：

```go
// 配置速率限制
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100           // 每个窗口最多100个令牌
config.RateLimitWindow = time.Minute // 每用户速率限制窗口

// 创建带速率限制的处理器
processor, err := jwt.New(secretKey, config)
if err != nil {
    panic(err)
}
defer processor.Close()

// 操作按UserID进行速率限制
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    // 用户已超出速率限制
    log.Printf("用户速率限制超出: %s", claims.UserID)
}
```

### 生产环境配置
结合速率限制和黑名单管理：

```go
// 完整的生产环境配置
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100
config.RateLimitWindow = time.Minute

blacklistConfig := jwt.DefaultBlacklistConfig()

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
if err != nil {
    panic(err)
}
defer processor.Close()

// 速率限制和令牌撤销同时生效
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    // 处理速率限制
}

err = processor.RevokeToken(token)
if err != nil {
    // 处理撤销错误
}
```

## 🔗 HTTP服务器集成 - 简单示例

### Gin框架示例
```go
func JWTMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        token = strings.TrimPrefix(token, "Bearer ")

        // 验证 JwtToken
        claims, valid, err := jwt.ValidateToken(secretKey, token)
        if err != nil || !valid {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("user", claims)
        c.Next()
    }
}

// 使用中间件
r.Use(JWTMiddleware())
```

### 基本HTTP服务器
```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    claims := jwt.Claims{
        UserID:   "user123",
        Username: "john_doe",
        Role:     "admin",
    }

    token, err := jwt.CreateToken(secretKey, claims)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{
        "access_token": token,
        "token_type":   "Bearer",
    })
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    
    claims, valid, err := jwt.ValidateToken(secretKey, tokenString)
    if err != nil || !valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "Access granted",
        "user":    claims.Username,
        "role":    claims.Role,
    })
}
```

## 🛡️ 安全特性

本库实现了多层安全防护：

### 输入验证
- **密钥要求**：最少32字节，带熵值验证
- **声明验证**：字符串长度限制、数组大小限制、控制字符过滤
- **模式检测**：阻止可疑模式（XSS、SQL注入、路径遍历）
- **大小限制**：每个字符串字段最多256字节，每个数组最多100项，最多50个额外字段

### 令牌安全
- **算法验证**：严格的签名方法验证（防止算法混淆攻击）
- **令牌撤销**：支持黑名单，可配置清理
- **过期强制执行**：自动验证 `exp`、`nbf` 和 `iat` 声明
- **签发者验证**：可选的签发者声明验证

### 运营安全
- **速率限制**：令牌桶算法，按用户限制
- **线程安全**：所有操作都是协程安全的
- **安全清理**：处理器关闭时密钥被清零
- **资源限制**：可配置的黑名单大小和缓存限制

### 标准合规性
- 遵循 JWT RFC 7519 规范
- 实现 HMAC-SHA256/384/512 签名方法
- 按规范验证注册声明

## 📚 详细文档

| 文档 | 内容 | 适用场景 |
|------|------|----------|
| [API参考](docs/API.md) | 完整API文档 | 开发时查阅 |
| [安全指南](docs/SECURITY.md) | 安全特性详解 | 安全审计 |
| [性能指南](docs/PERFORMANCE.md) | 性能优化技巧 | 高并发场景 |
| [集成示例](docs/EXAMPLES.md) | 各框架集成代码 | 项目集成 |
| [最佳实践](docs/BEST_PRACTICES.md) | 生产环境指南 | 部署上线 |
| [故障排除](docs/TROUBLESHOOTING.md) | 常见问题解决 | 问题诊断 |



---

## 📄 许可证

本项目采用 MIT 许可证 - 详情请查看 [LICENSE](LICENSE) 文件。

---

## 🤝 贡献

欢迎贡献代码！请随时提交 Pull Request。对于重大更改，请先开启 issue 讨论您想要更改的内容。

## 🌟 Star 历史

如果您觉得这个项目有用，请考虑给它一个 star！⭐

---

**由 CyberGoDev 团队用 ❤️ 制作**