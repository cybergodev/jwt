# JWT Library - Integration Examples

This guide provides practical integration examples for common use cases.

## 🌟 Web Frameworks

### Gin Framework

```go
package main

import (
    "log"
    "net/http"
    "os"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/cybergodev/jwt"
)

var processor *jwt.Processor

func init() {
    secretKey := os.Getenv("JWT_SECRET_KEY")
    if secretKey == "" {
        log.Fatal("JWT_SECRET_KEY required")
    }

    var err error
    processor, err = jwt.New(secretKey)
    if err != nil {
        log.Fatal(err)
    }
}

func JWTMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
            c.Abort()
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        claims, valid, err := processor.ValidateToken(token)
        if err != nil || !valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
            c.Abort()
            return
        }

        c.Set("claims", claims)
        c.Next()
    }
}

func main() {
    defer processor.Close()

    r := gin.Default()

    // Public routes
    r.POST("/login", loginHandler)

    // Protected routes
    protected := r.Group("/api")
    protected.Use(JWTMiddleware())
    {
        protected.GET("/profile", getProfile)
    }

    r.Run(":8080")
}

func loginHandler(c *gin.Context) {
    // Authenticate user (implement your logic)
    userID := "user123"

    // Create token
    claims := jwt.Claims{
        Subject: userID,
    }
    token, err := processor.CreateToken(claims)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "token creation failed"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "access_token": token,
        "token_type":   "Bearer",
    })
}

func getProfile(c *gin.Context) {
    claims, _ := c.Get("claims")
    userClaims := claims.(*jwt.Claims)

    c.JSON(http.StatusOK, gin.H{
        "user_id": userClaims.Subject,
    })
}
```

### Echo Framework

```go
package main

import (
    "net/http"
    "os"
    "strings"

    "github.com/labstack/echo/v4"
    "github.com/cybergodev/jwt"
)

var processor *jwt.Processor

func init() {
    secretKey := os.Getenv("JWT_SECRET_KEY")
    processor, _ = jwt.New(secretKey)
}

func JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        authHeader := c.Request().Header.Get("Authorization")
        if authHeader == "" {
            return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing token"})
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        claims, valid, err := processor.ValidateToken(token)
        if err != nil || !valid {
            return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
        }

        c.Set("claims", claims)
        return next(c)
    }
}

func main() {
    defer processor.Close()

    e := echo.New()

    e.POST("/login", loginHandler)

    protected := e.Group("/api")
    protected.Use(JWTMiddleware)
    protected.GET("/profile", getProfile)

    e.Start(":8080")
}
```

### Standard net/http

```go
package main

import (
    "encoding/json"
    "net/http"
    "os"
    "strings"

    "github.com/cybergodev/jwt"
)

var processor *jwt.Processor

func init() {
    secretKey := os.Getenv("JWT_SECRET_KEY")
    processor, _ = jwt.New(secretKey)
}

func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "missing token", http.StatusUnauthorized)
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        claims, valid, err := processor.ValidateToken(token)
        if err != nil || !valid {
            http.Error(w, "invalid token", http.StatusUnauthorized)
            return
        }

        // Store claims in context
        ctx := context.WithValue(r.Context(), "claims", claims)
        next(w, r.WithContext(ctx))
    }
}

func main() {
    defer processor.Close()

    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/api/profile", JWTMiddleware(getProfile))

    http.ListenAndServe(":8080", nil)
}
```

## 🔐 Common Patterns

### Role-Based Access Control

```go
func RequireRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, _ := c.Get("claims")
        userClaims := claims.(*jwt.Claims)

        if userClaims.Role != role {
            c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
            c.Abort()
            return
        }

        c.Next()
    }
}

// Usage
admin := r.Group("/admin")
admin.Use(JWTMiddleware())
admin.Use(RequireRole("admin"))
admin.GET("/users", listUsers)
```

### Token Refresh

```go
func refreshHandler(c *gin.Context) {
    refreshToken := c.PostForm("refresh_token")

    claims, valid, err := processor.ValidateToken(refreshToken)
    if err != nil || !valid {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
        return
    }

    // Create new access token
    newToken, err := processor.CreateToken(*claims)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "token creation failed"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"access_token": newToken})
}
```

---

For more details, see [API.md](API.md) and [BEST_PRACTICES.md](BEST_PRACTICES.md).