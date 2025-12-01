package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cybergodev/jwt"
)

// Web server JWT authentication example
// Demonstrates how to use JWT for user authentication in HTTP servers

var (
	secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
	processor *jwt.Processor
)

// User information structure
type User struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// Login request structure
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login response structure
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	User      User   `json:"user"`
}

// Error response structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func init() {
	// Initialize JWT processor
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  30 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "web-server-example",
		SigningMethod:   jwt.SigningMethodHS256,
	}

	// Web servers need rate limiting protection
	config.EnableRateLimit = true
	config.RateLimitRate = 100
	config.RateLimitWindow = time.Minute

	var err error
	processor, err = jwt.NewWithBlacklist(
		secretKey,
		jwt.DefaultBlacklistConfig(),
		config,
	)
	if err != nil {
		log.Fatalf("JWT processor initialization failed: %v", err)
	}
}

func main() {
	fmt.Println("🚀 Starting JWT Web Server Example")
	fmt.Println("========================")

	// Setup routes
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/profile", authMiddleware(profileHandler))
	http.HandleFunc("/admin", authMiddleware(requireRole("admin", adminHandler)))
	http.HandleFunc("/logout", authMiddleware(logoutHandler))
	http.HandleFunc("/", homeHandler)

	// Start server
	port := ":8080"
	fmt.Printf("Server started on port %s\n", port)
	fmt.Println("\nAvailable endpoints:")
	fmt.Println("POST /login    - User login")
	fmt.Println("GET  /profile  - Get user information (requires authentication)")
	fmt.Println("GET  /admin    - Admin page (requires admin role)")
	fmt.Println("POST /logout   - User logout (requires authentication)")
	fmt.Println("GET  /         - Home page")
	fmt.Println("\nTest command:")
	fmt.Println("curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"password\"}'")

	log.Fatal(http.ListenAndServe(port, nil))
}

// Home page handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"message": "Welcome to JWT Web Server Example",
		"version": "1.0.0",
	}
	json.NewEncoder(w).Encode(response)
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method supported", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid_request", "Invalid request format")
		return
	}

	// Simple user authentication (production should query database)
	user, ok := authenticateUser(req.Username, req.Password)
	if !ok {
		sendError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid username or password")
		return
	}

	// Create JWT Claims
	claims := jwt.Claims{
		UserID:      user.ID,
		Username:    user.Username,
		Role:        user.Role,
		Permissions: user.Permissions,
		SessionID:   fmt.Sprintf("session_%d", time.Now().Unix()),
		ClientID:    "web_client",
		Extra: map[string]any{
			"email": user.Email,
		},
	}

	// Generate Token
	token, err := processor.CreateToken(claims)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "token_generation_failed", "Token generation failed")
		return
	}

	// Return login response
	response := LoginResponse{
		Token:     token,
		ExpiresAt: time.Now().Add(30 * time.Minute).Format(time.RFC3339),
		User:      user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// User profile handler
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Get user information from context
	claimsValue := r.Context().Value("claims")
	if claimsValue == nil {
		sendError(w, http.StatusUnauthorized, "unauthorized", "User information not found")
		return
	}

	claims, ok := claimsValue.(*jwt.Claims)
	if !ok {
		sendError(w, http.StatusInternalServerError, "internal_error", "User information format error")
		return
	}

	// Safely get email, avoid type assertion panic
	var email string
	if emailValue, exists := claims.Extra["email"]; exists {
		if emailStr, ok := emailValue.(string); ok {
			email = emailStr
		}
	}

	user := User{
		ID:          claims.UserID,
		Username:    claims.Username,
		Email:       email,
		Role:        claims.Role,
		Permissions: claims.Permissions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Admin handler
func adminHandler(w http.ResponseWriter, r *http.Request) {
	claimsValue := r.Context().Value("claims")
	if claimsValue == nil {
		sendError(w, http.StatusUnauthorized, "unauthorized", "User information not found")
		return
	}

	claims, ok := claimsValue.(*jwt.Claims)
	if !ok {
		sendError(w, http.StatusInternalServerError, "internal_error", "User information format error")
		return
	}

	response := map[string]any{
		"message":     "Welcome to admin page",
		"admin":       claims.Username,
		"permissions": claims.Permissions,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Logout handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method supported", http.StatusMethodNotAllowed)
		return
	}

	// Get Token
	token := extractToken(r)
	if token == "" {
		sendError(w, http.StatusBadRequest, "missing_token", "Missing token")
		return
	}

	// Revoke Token
	err := processor.RevokeToken(token)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "logout_failed", "Logout failed")
		return
	}

	response := map[string]string{
		"message": "Logout successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Simple user authentication function (production should query database)
func authenticateUser(username, password string) (User, bool) {
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
	if !exists || password != "password" { // Simple password verification
		return User{}, false
	}

	return user, true
}

// Send error response
func sendError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := ErrorResponse{
		Error:   errorCode,
		Message: message,
	}

	json.NewEncoder(w).Encode(response)
}

// Extract Token from request
func extractToken(r *http.Request) string {
	// Extract from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1]
		}
	}

	// Extract from query parameters
	return r.URL.Query().Get("token")
}

// Authentication middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Token
		token := extractToken(r)
		if token == "" {
			sendError(w, http.StatusUnauthorized, "missing_token", "Missing authentication token")
			return
		}

		// Validate Token
		claims, valid, err := processor.ValidateToken(token)
		if err != nil || !valid {
			sendError(w, http.StatusUnauthorized, "invalid_token", "Invalid token")
			return
		}

		// Add claims to request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "claims", claims)
		r = r.WithContext(ctx)

		// Call next handler
		next(w, r)
	}
}

// Role check middleware
func requireRole(requiredRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claimsValue := r.Context().Value("claims")
		if claimsValue == nil {
			sendError(w, http.StatusUnauthorized, "unauthorized", "User information not found")
			return
		}

		claims, ok := claimsValue.(*jwt.Claims)
		if !ok {
			sendError(w, http.StatusInternalServerError, "internal_error", "User information format error")
			return
		}

		if claims.Role != requiredRole {
			sendError(w, http.StatusForbidden, "insufficient_permissions",
				fmt.Sprintf("Requires %s role", requiredRole))
			return
		}

		next(w, r)
	}
}
