# JWT Library - Integration Examples

Real-world integration examples with popular Go frameworks and patterns.

## Table of Contents

- [Standard Library (net/http)](#standard-library-nethttp)
- [Gin Framework](#gin-framework)
- [Echo Framework](#echo-framework)
- [Chi Router](#chi-router)
- [gRPC Integration](#grpc-integration)
- [GraphQL Integration](#graphql-integration)
- [WebSocket Authentication](#websocket-authentication)

---

## Standard Library (net/http)

### Basic Setup

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/cybergodev/jwt"
)

type Handler struct {
    processor *jwt.Processor
}

type contextKey string

const claimsKey contextKey = "claims"

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
    cfg.AccessTokenTTL = 15 * time.Minute
    cfg.RefreshTokenTTL = 7 * 24 * time.Hour

    processor, err := jwt.New(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer processor.Close()

    handler := &Handler{processor: processor}

    http.HandleFunc("/login", handler.login)
    http.HandleFunc("/refresh", handler.refresh)
    http.HandleFunc("/protected", handler.authMiddleware(handler.protected))
    http.HandleFunc("/logout", handler.authMiddleware(handler.logout))

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Verify credentials (implement your own logic)
    if !verifyCredentials(creds.Username, creds.Password) {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Create claims
    claims := &jwt.Claims{
        UserID:   getUserID(creds.Username),
        Username: creds.Username,
        Role:     getUserRole(creds.Username),
    }

    // Create tokens
    accessToken, err := h.processor.Create(claims)
    if err != nil {
        http.Error(w, "Failed to create token", http.StatusInternalServerError)
        return
    }

    refreshToken, err := h.processor.CreateRefresh(claims)
    if err != nil {
        http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "token_type":    "Bearer",
        "expires_in":    "900", // 15 minutes in seconds
    })
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
    var req struct {
        RefreshToken string `json:"refresh_token"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    newAccessToken, err := h.processor.Refresh(req.RefreshToken)
    if err != nil {
        http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{
        "access_token": newAccessToken,
        "token_type":   "Bearer",
        "expires_in":   "900",
    })
}

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        if token == authHeader {
            http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
            return
        }

        claims, valid, err := h.processor.Validate(token)
        if err != nil || !valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Add claims to request context
        ctx := context.WithValue(r.Context(), claimsKey, claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

func (h *Handler) protected(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value(claimsKey).(jwt.Claims)

    json.NewEncoder(w).Encode(map[string]string{
        "message":  "Access granted",
        "user_id":  claims.UserID,
        "username": claims.Username,
        "role":     claims.Role,
    })
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    token := strings.TrimPrefix(authHeader, "Bearer ")

    if err := h.processor.Revoke(token); err != nil {
        http.Error(w, "Failed to logout", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}
```

---

## Gin Framework

### Middleware Setup

```go
package main

import (
    "log"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/cybergodev/jwt"
)

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    r := gin.Default()

    // Public routes
    r.POST("/login", loginHandler(processor))

    // Protected routes
    protected := r.Group("/api")
    protected.Use(JWTMiddleware(processor))
    {
        protected.GET("/profile", profileHandler)
        protected.POST("/logout", logoutHandler(processor))
    }

    // Admin routes
    admin := r.Group("/admin")
    admin.Use(JWTMiddleware(processor))
    admin.Use(RoleMiddleware("admin"))
    {
        admin.GET("/users", listUsersHandler)
    }

    r.Run(":8080")
}

func JWTMiddleware(processor *jwt.Processor) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(401, gin.H{"error": "Missing authorization header"})
            c.Abort()
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        if token == authHeader {
            c.JSON(401, gin.H{"error": "Invalid authorization format"})
            c.Abort()
            return
        }

        claims, valid, err := processor.Validate(token)
        if err != nil || !valid {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("claims", claims)
        c.Next()
    }
}

func RoleMiddleware(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, exists := c.Get("claims")
        if !exists {
            c.JSON(401, gin.H{"error": "No claims found"})
            c.Abort()
            return
        }

        jwtClaims := claims.(jwt.Claims)
        if jwtClaims.Role != requiredRole {
            c.JSON(403, gin.H{"error": "Insufficient permissions"})
            c.Abort()
            return
        }

        c.Next()
    }
}

func loginHandler(processor *jwt.Processor) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req struct {
            Username string `json:"username" binding:"required"`
            Password string `json:"password" binding:"required"`
        }

        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(400, gin.H{"error": "Invalid request"})
            return
        }

        // Verify credentials
        if !verifyCredentials(req.Username, req.Password) {
            c.JSON(401, gin.H{"error": "Invalid credentials"})
            return
        }

        claims := &jwt.Claims{
            UserID:   getUserID(req.Username),
            Username: req.Username,
            Role:     getUserRole(req.Username),
        }

        accessToken, _ := processor.Create(claims)
        refreshToken, _ := processor.CreateRefresh(claims)

        c.JSON(200, gin.H{
            "access_token":  accessToken,
            "refresh_token": refreshToken,
            "token_type":    "Bearer",
            "expires_in":    900,
        })
    }
}

func profileHandler(c *gin.Context) {
    claims := c.MustGet("claims").(jwt.Claims)
    c.JSON(200, gin.H{
        "user_id":  claims.UserID,
        "username": claims.Username,
        "role":     claims.Role,
    })
}

func logoutHandler(processor *jwt.Processor) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        token := strings.TrimPrefix(authHeader, "Bearer ")

        if err := processor.Revoke(token); err != nil {
            c.JSON(500, gin.H{"error": "Failed to logout"})
            return
        }

        c.Status(204)
    }
}
```

---

## Echo Framework

```go
package main

import (
    "log"
    "strings"
    "time"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "github.com/cybergodev/jwt"
)

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    e := echo.New()
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    // Public routes
    e.POST("/login", loginHandler(processor))
    e.POST("/refresh", refreshHandler(processor))

    // Protected routes
    restricted := e.Group("/api")
    restricted.Use(JWTMiddleware(processor))
    restricted.GET("/profile", profileHandler)
    restricted.POST("/logout", logoutHandler(processor))

    e.Logger.Fatal(e.Start(":8080"))
}

func JWTMiddleware(processor *jwt.Processor) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            authHeader := c.Request().Header.Get("Authorization")
            if authHeader == "" {
                return echo.NewHTTPError(401, "Missing authorization header")
            }

            token := strings.TrimPrefix(authHeader, "Bearer ")
            if token == authHeader {
                return echo.NewHTTPError(401, "Invalid authorization format")
            }

            claims, valid, err := processor.Validate(token)
            if err != nil || !valid {
                return echo.NewHTTPError(401, "Invalid token")
            }

            c.Set("claims", claims)
            return next(c)
        }
    }
}

func loginHandler(processor *jwt.Processor) echo.HandlerFunc {
    return func(c echo.Context) error {
        var req struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }

        if err := c.Bind(&req); err != nil {
            return echo.NewHTTPError(400, "Invalid request")
        }

        if !verifyCredentials(req.Username, req.Password) {
            return echo.NewHTTPError(401, "Invalid credentials")
        }

        claims := &jwt.Claims{
            UserID:   getUserID(req.Username),
            Username: req.Username,
        }

        accessToken, _ := processor.Create(claims)
        refreshToken, _ := processor.CreateRefresh(claims)

        return c.JSON(200, map[string]interface{}{
            "access_token":  accessToken,
            "refresh_token": refreshToken,
            "token_type":    "Bearer",
        })
    }
}

func profileHandler(c echo.Context) error {
    claims := c.Get("claims").(jwt.Claims)
    return c.JSON(200, map[string]interface{}{
        "user_id":  claims.UserID,
        "username": claims.Username,
    })
}
```

---

## Chi Router

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "strings"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/cybergodev/jwt"
)

type contextKey string

const claimsKey contextKey = "claims"

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)

    // Public routes
    r.Post("/login", loginHandler(processor))
    r.Post("/refresh", refreshHandler(processor))

    // Protected routes
    r.Group(func(r chi.Router) {
        r.Use(AuthMiddleware(processor))
        r.Get("/api/profile", profileHandler)
        r.Post("/api/logout", logoutHandler(processor))
    })

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", r))
}

func AuthMiddleware(processor *jwt.Processor) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Missing authorization header", http.StatusUnauthorized)
                return
            }

            token := strings.TrimPrefix(authHeader, "Bearer ")
            if token == authHeader {
                http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
                return
            }

            claims, valid, err := processor.Validate(token)
            if err != nil || !valid {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            ctx := context.WithValue(r.Context(), claimsKey, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value(claimsKey).(jwt.Claims)
    json.NewEncoder(w).Encode(map[string]string{
        "user_id":  claims.UserID,
        "username": claims.Username,
    })
}
```

---

## gRPC Integration

```go
package main

import (
    "context"
    "log"
    "net"
    "strings"

    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
    "github.com/cybergodev/jwt"
)

type contextKey string

const claimsKey contextKey = "claims"

type server struct {
    pb.UnimplementedUserServiceServer
    processor *jwt.Processor
}

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    lis, _ := net.Listen("tcp", ":50051")

    s := grpc.NewServer(
        grpc.UnaryInterceptor(AuthInterceptor(processor)),
    )

    pb.RegisterUserServiceServer(s, &server{processor: processor})

    log.Println("gRPC server starting on :50051")
    s.Serve(lis)
}

func AuthInterceptor(processor *jwt.Processor) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        // Skip auth for certain methods
        if info.FullMethod == "/pb.UserService/Login" {
            return handler(ctx, req)
        }

        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "Missing metadata")
        }

        values := md.Get("authorization")
        if len(values) == 0 {
            return nil, status.Error(codes.Unauthenticated, "Missing authorization header")
        }

        token := strings.TrimPrefix(values[0], "Bearer ")
        claims, valid, err := processor.Validate(token)
        if err != nil || !valid {
            return nil, status.Error(codes.Unauthenticated, "Invalid token")
        }

        ctx = context.WithValue(ctx, claimsKey, claims)
        return handler(ctx, req)
    }
}

func (s *server) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.ProfileResponse, error) {
    claims, ok := ctx.Value(claimsKey).(jwt.Claims)
    if !ok {
        return nil, status.Error(codes.Internal, "Failed to get claims")
    }

    return &pb.ProfileResponse{
        UserId:   claims.UserID,
        Username: claims.Username,
        Role:     claims.Role,
    }, nil
}
```

---

## GraphQL Integration

```go
package main

import (
    "context"
    "log"
    "net/http"
    "strings"

    "github.com/graphql-go/graphql"
    "github.com/graphql-go/handler"
    "github.com/cybergodev/jwt"
)

type contextKey string

const claimsKey contextKey = "claims"

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    // Schema definition
    userType := graphql.NewObject(graphql.ObjectConfig{
        Name: "User",
        Fields: graphql.Fields{
            "id":       &graphql.Field{Type: graphql.String},
            "username": &graphql.Field{Type: graphql.String},
            "role":     &graphql.Field{Type: graphql.String},
        },
    })

    queryType := graphql.NewObject(graphql.ObjectConfig{
        Name: "Query",
        Fields: graphql.Fields{
            "me": &graphql.Field{
                Type: userType,
                Resolve: func(p graphql.ResolveParams) (interface{}, error) {
                    claims, ok := p.Context.Value(claimsKey).(jwt.Claims)
                    if !ok {
                        return nil, nil
                    }
                    return map[string]string{
                        "id":       claims.UserID,
                        "username": claims.Username,
                        "role":     claims.Role,
                    }, nil
                },
            },
        },
    })

    schema, _ := graphql.NewSchema(graphql.SchemaConfig{
        Query: queryType,
    })

    h := handler.New(&handler.Config{
        Schema:   &schema,
        Pretty:   true,
        GraphiQL: true,
    })

    // Wrap with auth middleware
    http.Handle("/graphql", AuthMiddleware(processor, h))

    log.Println("GraphQL server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func AuthMiddleware(processor *jwt.Processor, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader != "" {
            token := strings.TrimPrefix(authHeader, "Bearer ")
            claims, valid, _ := processor.Validate(token)
            if valid {
                ctx := context.WithValue(r.Context(), claimsKey, claims)
                r = r.WithContext(ctx)
            }
        }
        next.ServeHTTP(w, r)
    })
}
```

---

## WebSocket Authentication

```go
package main

import (
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/gorilla/websocket"
    "github.com/cybergodev/jwt"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return true // Configure appropriately for production
    },
}

type WSClient struct {
    conn   *websocket.Conn
    claims jwt.Claims
}

func main() {
    cfg := jwt.DefaultConfig()
    cfg.SecretKey = "your-secret-key-at-least-32-bytes-long!!"
    processor, _ := jwt.New(cfg)
    defer processor.Close()

    http.HandleFunc("/ws", wsHandler(processor))

    log.Println("WebSocket server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func wsHandler(processor *jwt.Processor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Get token from query parameter (for WebSocket)
        token := r.URL.Query().Get("token")
        if token == "" {
            http.Error(w, "Missing token", http.StatusUnauthorized)
            return
        }

        claims, valid, err := processor.Validate(token)
        if err != nil || !valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Upgrade to WebSocket
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            log.Printf("Upgrade error: %v", err)
            return
        }

        client := &WSClient{
            conn:   conn,
            claims: claims,
        }

        // Handle connection
        go client.handle()
    }
}

func (c *WSClient) handle() {
    defer c.conn.Close()

    log.Printf("WebSocket connected: user=%s", c.claims.UserID)

    for {
        messageType, message, err := c.conn.ReadMessage()
        if err != nil {
            log.Printf("Read error: %v", err)
            break
        }

        // Process message with claims context
        log.Printf("Received from %s: %s", c.claims.UserID, string(message))

        // Echo back
        err = c.conn.WriteMessage(messageType, message)
        if err != nil {
            log.Printf("Write error: %v", err)
            break
        }
    }
}
```

---

## Complete Web Server Example

See [examples/6_web_server.go](../examples/6_web_server.go) for a complete working example.

---
