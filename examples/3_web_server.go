package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cybergodev/jwt"
)

// Production-ready web server with JWT authentication
// Demonstrates: authentication flow, middleware, RBAC, graceful shutdown

var processor *jwt.Processor

// User represents application user data
type User struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents successful login response
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	User         User   `json:"user"`
}

// ErrorResponse represents error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func init() {
	// Initialize JWT processor with production configuration
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		// Demo key - use environment variable in production
		secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
		log.Println("⚠️  Using demo secret key - set JWT_SECRET_KEY in production")
	}

	// Production configuration with rate limiting
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "web-server-example",
		SigningMethod:   jwt.SigningMethodHS256,
		EnableRateLimit: true,
		RateLimitRate:   100,
		RateLimitWindow: time.Minute,
	}

	blacklistConfig := jwt.BlacklistConfig{
		MaxSize:           10000,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
	}

	var err error
	processor, err = jwt.NewWithBlacklist(secretKey, blacklistConfig, config)
	if err != nil {
		log.Fatalf("Failed to initialize JWT processor: %v", err)
	}

	log.Println("✅ JWT processor initialized")
}

func main() {
	fmt.Println("🚀 JWT Web Server - Production Example")
	fmt.Println("=======================================\n ")

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/profile", authMiddleware(profileHandler))
	mux.HandleFunc("/admin", authMiddleware(requireRole("admin", adminHandler)))
	mux.HandleFunc("/logout", authMiddleware(logoutHandler))

	// Create HTTP server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Println("🌐 Server listening on http://localhost:8080")
		log.Println("\n📋 Available endpoints:")
		log.Println("  POST /login    - User login")
		log.Println("  GET  /profile  - User profile (requires auth)")
		log.Println("  GET  /admin    - Admin page (requires admin role)")
		log.Println("  POST /logout   - User logout (requires auth)")
		log.Println("\n💡 Test with:")
		log.Println(`  curl -X POST http://localhost:8080/login \`)
		log.Println(`    -H "Content-Type: application/json" \`)
		log.Println(`    -d '{"username":"admin","password":"password"}'`)
		log.Println()

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("\n🛑 Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	// Close JWT processor
	if err := processor.Close(); err != nil {
		log.Printf("Processor close error: %v", err)
	}

	log.Println("✅ Server gracefully stopped")
}

// homeHandler serves the home page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "JWT Web Server Example",
		"version": "1.0.0",
	})
}

// loginHandler authenticates users and issues JWT tokens
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method supported")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON format")
		return
	}

	// Authenticate user (mock implementation - replace with real auth)
	user, ok := authenticateUser(req.Username, req.Password)
	if !ok {
		sendError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid username or password")
		return
	}

	// Create JWT claims
	claims := jwt.Claims{
		UserID:      user.ID,
		Username:    user.Username,
		Role:        user.Role,
		Permissions: user.Permissions,
		SessionID:   fmt.Sprintf("session_%d", time.Now().Unix()),
		Extra: map[string]any{
			"email": user.Email,
		},
	}

	// Generate access token
	accessToken, err := processor.CreateToken(claims)
	if err != nil {
		log.Printf("Token creation failed: %v", err)
		sendError(w, http.StatusInternalServerError, "token_generation_failed", "Failed to generate token")
		return
	}

	// Generate refresh token
	refreshToken, err := processor.CreateRefreshToken(claims)
	if err != nil {
		log.Printf("Refresh token creation failed: %v", err)
		sendError(w, http.StatusInternalServerError, "token_generation_failed", "Failed to generate refresh token")
		return
	}

	// Send response
	response := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 minutes
		User:         user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ User logged in: %s", user.Username)
}

// profileHandler returns authenticated user's profile
func profileHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*jwt.Claims)

	user := User{
		ID:          claims.UserID,
		Username:    claims.Username,
		Role:        claims.Role,
		Permissions: claims.Permissions,
	}

	if email, ok := claims.Extra["email"].(string); ok {
		user.Email = email
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// adminHandler handles admin-only requests
func adminHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*jwt.Claims)

	response := map[string]any{
		"message":     "Welcome to admin dashboard",
		"admin":       claims.Username,
		"permissions": claims.Permissions,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// logoutHandler revokes the user's token
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method supported")
		return
	}

	token := extractToken(r)
	if token == "" {
		sendError(w, http.StatusBadRequest, "missing_token", "Token not found")
		return
	}

	// Revoke token
	if err := processor.RevokeToken(token); err != nil {
		log.Printf("Token revocation failed: %v", err)
		sendError(w, http.StatusInternalServerError, "logout_failed", "Failed to logout")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Successfully logged out",
	})
	log.Println("✅ User logged out")
}

// authMiddleware validates JWT tokens
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			sendError(w, http.StatusUnauthorized, "missing_token", "Authorization token required")
			return
		}

		claims, valid, err := processor.ValidateToken(token)
		if err != nil || !valid {
			sendError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next(w, r.WithContext(ctx))
	}
}

// requireRole checks if user has required role
func requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("claims").(*jwt.Claims)

		if claims.Role != role {
			sendError(w, http.StatusForbidden, "insufficient_permissions",
				fmt.Sprintf("Requires %s role", role))
			return
		}

		next(w, r)
	}
}

// extractToken extracts JWT from Authorization header
func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}

	return ""
}

// sendError sends JSON error response
func sendError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errorCode,
		Message: message,
	})
}

// authenticateUser validates credentials (mock implementation)
func authenticateUser(username, password string) (User, bool) {
	// Mock user database - replace with real authentication
	users := map[string]User{
		"admin": {
			ID:          "1",
			Username:    "admin",
			Email:       "admin@example.com",
			Role:        "admin",
			Permissions: []string{"read", "write", "delete", "admin"},
		},
		"user": {
			ID:          "2",
			Username:    "user",
			Email:       "user@example.com",
			Role:        "user",
			Permissions: []string{"read"},
		},
	}

	user, exists := users[username]
	if !exists || password != "password" {
		return User{}, false
	}

	return user, true
}
