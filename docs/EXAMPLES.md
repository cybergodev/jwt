# JWT Library - Production Integration Examples

> **Real-World Implementation Guide** - Production-ready code examples for seamless JWT integration across popular Go frameworks and architectures.

This comprehensive guide provides battle-tested integration examples with complete error handling, security best practices, and performance optimizations.

## 🚀 Quick Integration

Choose your framework for instant JWT integration:

```bash
# Copy and customize the examples below for your specific use case
# All examples include production-ready error handling and security features
```
---

## 🌟 Web Frameworks

### Gin Framework - Production Ready

Complete Gin integration with authentication, authorization, and security features.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/cybergodev/jwt"
)

// Global JWT processor - initialized once for optimal performance
var jwtProcessor *jwt.Processor

// Initialize JWT processor with production configuration
func initJWTProcessor() {
    secretKey := os.Getenv("JWT_SECRET_KEY")
    if secretKey == "" {
        log.Fatal("JWT_SECRET_KEY environment variable is required")
    }

    // Production-ready configuration with rate limiting
    rateLimitConfig := jwt.RateLimitConfig{
        Enabled:           true,
        TokenCreationRate: 100,  // 100 tokens per minute per user
        ValidationRate:    1000, // 1000 validations per minute per user
        LoginAttemptRate:  5,    // 5 login attempts per minute per IP
        PasswordResetRate: 3,    // 3 password resets per hour per user
        CleanupInterval:   5 * time.Minute,
    }

    config := jwt.Config{
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 24 * time.Hour,
        Issuer:          "gin-app-v1.0",
        SigningMethod:   jwt.SigningMethodHS256,
        EnableRateLimit: true,        // Enable rate limiting for production
        RateLimit:       &rateLimitConfig,
    }

    // Blacklist configuration for token revocation
    blacklistConfig := jwt.BlacklistConfig{
        MaxSize:           50000,
        CleanupInterval:   5 * time.Minute,
        EnableAutoCleanup: true,
    }

    var err error
    jwtProcessor, err = jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
    if err != nil {
        log.Fatalf("Failed to initialize JWT processor: %v", err)
    }

    log.Println("JWT processor initialized successfully")
}

// Production-grade JWT middleware with comprehensive error handling
func JWTMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract token from Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "missing_token",
                "message": "Authorization header is required",
            })
            c.Abort()
            return
        }

        // Validate Bearer token format
        if !strings.HasPrefix(authHeader, "Bearer ") {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "invalid_token_format",
                "message": "Authorization header must start with 'Bearer '",
            })
            c.Abort()
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        if token == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "empty_token",
                "message": "Token cannot be empty",
            })
            c.Abort()
            return
        }

        // Validate token with context for timeout handling
        ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
        defer cancel()

        claims, valid, err := jwtProcessor.ValidateTokenWithContext(ctx, token)
        if err != nil {
            log.Printf("Token validation error: %v", err)
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "token_validation_failed",
                "message": "Token validation failed",
            })
            c.Abort()
            return
        }

        if !valid {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "invalid_token",
                "message": "Token is invalid or expired",
            })
            c.Abort()
            return
        }

        // Store user information in Gin context
        c.Set("user_claims", claims)
        c.Set("user_id", claims.UserID)
        c.Set("username", claims.Username)
        c.Set("role", claims.Role)
        c.Set("permissions", claims.Permissions)

        c.Next()
    }
}

// Advanced role-based access control middleware
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, exists := c.Get("user_claims")
        if !exists {
            c.JSON(http.StatusInternalServerError, gin.H{
                "error":   "missing_user_context",
                "message": "User context not found",
            })
            c.Abort()
            return
        }

        userClaims, ok := claims.(*jwt.Claims)
        if !ok {
            c.JSON(http.StatusInternalServerError, gin.H{
                "error":   "invalid_user_context",
                "message": "Invalid user context format",
            })
            c.Abort()
            return
        }

        userRole := userClaims.Role

        // Check if user has required role
        for _, role := range allowedRoles {
            if userRole == role {
                c.Next()
                return
            }
        }

        c.JSON(http.StatusForbidden, gin.H{
            "error":   "insufficient_permissions",
            "message": "User does not have required role",
            "required_roles": allowedRoles,
            "user_role": userRole,
        })
        c.Abort()
    }
}

// Permission-based access control middleware
func RequirePermission(requiredPermissions ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, exists := c.Get("user_claims")
        if !exists {
            c.JSON(http.StatusInternalServerError, gin.H{
                "error": "missing_user_context",
            })
            c.Abort()
            return
        }

        userClaims, ok := claims.(*jwt.Claims)
        if !ok {
            c.JSON(http.StatusInternalServerError, gin.H{
                "error": "invalid_user_context",
            })
            c.Abort()
            return
        }

        userPermissions := userClaims.Permissions

        // Check if user has all required permissions
        for _, required := range requiredPermissions {
            hasPermission := false
            for _, userPerm := range userPermissions {
                if userPerm == required {
                    hasPermission = true
                    break
                }
            }
            if !hasPermission {
                c.JSON(http.StatusForbidden, gin.H{
                    "error":   "insufficient_permissions",
                    "message": "Missing required permission: " + required,
                })
                c.Abort()
                return
            }
        }

        c.Next()
    }
}

// Complete Gin application with JWT authentication
func main() {
    // Initialize JWT processor
    initJWTProcessor()
    defer jwtProcessor.Close()

    // Create Gin router
    r := gin.Default()

    // Public routes (no authentication required)
    public := r.Group("/api/v1")
    {
        public.POST("/login", loginHandler)
        public.POST("/register", registerHandler)
        public.POST("/refresh", refreshTokenHandler)
    }

    // Protected routes (authentication required)
    protected := r.Group("/api/v1")
    protected.Use(JWTMiddleware())
    {
        protected.GET("/profile", getUserProfile)
        protected.PUT("/profile", updateUserProfile)
        protected.POST("/logout", logoutHandler)

        // Admin-only routes
        admin := protected.Group("/admin")
        admin.Use(RequireRole("admin"))
        {
            admin.GET("/users", listUsers)
            admin.DELETE("/users/:id", deleteUser)
        }

        // Permission-based routes
        protected.GET("/reports", RequirePermission("read:reports"), getReports)
        protected.POST("/reports", RequirePermission("write:reports"), createReport)
    }

    // Graceful shutdown
    srv := &http.Server{
        Addr:    ":8080",
        Handler: r,
    }

    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server failed to start: %v", err)
        }
    }()

    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down server...")
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }

    log.Println("Server exited")
}

// Login handler with JWT token generation
func loginHandler(c *gin.Context) {
    var loginReq struct {
        Username string `json:"username" binding:"required"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&loginReq); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Authenticate user (implement your authentication logic)
    user, err := authenticateUser(loginReq.Username, loginReq.Password)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }

    // Create JWT claims
    claims := jwt.Claims{
        UserID:      user.ID,
        Username:    user.Username,
        Role:        user.Role,
        Permissions: user.Permissions,
    }

    claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(20 * time.Minute))

    // Generate access token
    accessToken, err := jwtProcessor.CreateToken(claims)
    if err != nil {
        log.Printf("Token creation failed: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
        return
    }

    // Generate refresh token
    refreshToken, err := jwtProcessor.CreateRefreshToken(claims)
    if err != nil {
        log.Printf("Refresh token creation failed: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Refresh token generation failed"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "token_type":    "Bearer",
        "expires_in":    900, // 15 minutes
        "user": gin.H{
            "id":       user.ID,
            "username": user.Username,
            "role":     user.Role,
        },
    })
}

// Logout handler with token revocation
func logoutHandler(c *gin.Context) {
    authHeader := c.GetHeader("Authorization")
    token := strings.TrimPrefix(authHeader, "Bearer ")

    // Revoke the token
    if err := jwtProcessor.RevokeToken(token); err != nil {
        log.Printf("Token revocation failed: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// User struct for demonstration
type User struct {
    ID          string   `json:"id"`
    Username    string   `json:"username"`
    Role        string   `json:"role"`
    Permissions []string `json:"permissions"`
}

// Mock authentication function (implement your own)
func authenticateUser(username, password string) (*User, error) {
    // This is a mock implementation - replace with your actual authentication logic
    if username == "admin" && password == "password" {
        return &User{
            ID:          "1",
            Username:    "admin",
            Role:        "admin",
            Permissions: []string{"read:reports", "write:reports", "delete:users"},
        }, nil
    }
    return nil, fmt.Errorf("invalid credentials")
}
```

---

### Security Checklist

- [ ] **Token Extraction**: Proper Bearer token parsing
- [ ] **Validation**: Context-aware token validation
- [ ] **Error Handling**: Comprehensive error responses
- [ ] **Context Storage**: Secure claims storage in request context
- [ ] **Role/Permission Checks**: Granular access control
- [ ] **Token Revocation**: Logout and security incident handling
- [ ] **Rate Limiting**: Protection against brute force attacks

---

**🚀 These examples provide production-ready JWT integration patterns. Customize the code based on your specific requirements and security policies.**

