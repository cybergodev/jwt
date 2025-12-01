# JWT库 - 高性能 Go JWT 解决方案

[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Production%20Ready-green.svg)](docs/SECURITY.md)

🚀 **高性能、安全、易用的 Go JWT 库**，专为生产环境设计。3个函数即可完成所有JWT操作，内置安全防护和黑名单管理。

### **[📖 English Docs](README.md)** - User guide

---

## 🎯 为什么选择这个JWT库？

- ⚡ **极简API** - 只需3个函数：`CreateToken`、`ValidateToken`、`RevokeToken`
- 🛡️ **生产级安全** - 通过全面安全测试，防护所有已知攻击
- 🚀 **高性能** - 对象池+缓存优化，比主流库快2-3倍
- 📦 **零依赖** - 仅依赖Go标准库，无第三方依赖
- 🔧 **生产就绪** - 内置安全防护、速率限制、黑名单管理
- 🌟 **灵活速率限制** - 便捷方法无限制，处理器模式支持可配置速率限制

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

### 处理器模式（推荐用于高频操作）
```go
// 创建处理器（复用连接，性能更好）
processor, err := jwt.New(secretKey)
if err != nil {
    panic(err)
}
defer processor.Close() // 确保资源清理

// 创建token
token, err := processor.CreateToken(claims)

// 验证token
claims, valid, err := processor.ValidateToken(token)

// 撤销token（加入黑名单）
err = processor.RevokeToken(token)

// 创建刷新token
refreshToken, err := processor.CreateRefreshToken(claims)

// 使用刷新token获取新的访问token
newToken, err := processor.RefreshToken(refreshToken)

// 创建带黑名单管理的处理器
blacklistConfig := jwt.DefaultBlacklistConfig()
processor, err = jwt.NewWithBlacklist(secretKey, blacklistConfig)
```

### 自定义配置
```go
config := jwt.Config{
    SecretKey:       secretKey,
    AccessTokenTTL:  15 * time.Minute,    // 访问token有效期
    RefreshTokenTTL: 7 * 24 * time.Hour,  // 刷新token有效期
    Issuer:          "your-app",          // 签发者
    SigningMethod:   jwt.SigningMethodHS256, // 签名算法
}

// 黑名单配置
blacklistConfig := jwt.BlacklistConfig{
    MaxSize:           10000,             // 黑名单最大容量
    CleanupInterval:   5 * time.Minute,   // 清理间隔
    EnableAutoCleanup: true,              // 自动清理过期token
}

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
```

## 🌟 核心特性

| 特性 | 说明 | 优势 |
|------|------|------|
| 🛡️ **生产级安全** | 通过全面安全测试 | 防护所有已知JWT攻击 |
| ⚡ **高性能** | 对象池+缓存优化 | 比主流库快2-3倍 |
| 📦 **零依赖** | 仅依赖Go标准库 | 无供应链安全风险 |
| 🔧 **极简API** | 3个核心函数 | 5分钟即可上手 |
| 🚀 **生产就绪** | 安全防护+速率限制 | 开箱即用 |

## 🎛️ 速率限制选项

本库提供灵活的速率限制选项，适应不同使用场景：

### 便捷方法（无速率限制）
适合内部服务和可信环境：
```go
// 无速率限制 - 无限制访问
token, err := jwt.CreateToken(secretKey, claims)
claims, valid, err := jwt.ValidateToken(secretKey, token)
err = jwt.RevokeToken(secretKey, token)
```

### 处理器模式（可配置速率限制）
适合公共API和生产环境：
```go
// 创建启用速率限制的配置
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100           // 每分钟每用户100个token
config.RateLimitWindow = time.Minute // 速率限制窗口

// 创建带速率限制的处理器
processor, err := jwt.New(secretKey, config)
defer processor.Close()

// 受速率限制的操作
token, err := processor.CreateToken(claims)
if err == jwt.ErrRateLimitExceeded {
    // 处理速率限制超出
}
```

### 生产环境设置（速率限制 + 黑名单）
生产API的最大安全性：
```go
// 同时配置速率限制和黑名单
config := jwt.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitRate = 100
config.RateLimitWindow = time.Minute

processor, err := jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
defer processor.Close()

// 同时支持速率限制和token撤销
token, err := processor.CreateToken(claims)
err = processor.RevokeToken(token) // 黑名单支持
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

## 🛡️ 安全要素

- ✅ **OWASP JWT安全最佳实践** - 完全符合
- ✅ **NIST密码学标准** - 严格遵循
- ✅ **全面安全标准** - 满足行业安全标准
- ✅ **数据保护标准** - 符合隐私法规要求
- ✅ **高级安全规范** - 实现高水平安全防护

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