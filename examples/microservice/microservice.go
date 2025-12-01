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

// Microservice JWT authentication example
// Demonstrates how to use JWT for inter-service authentication in microservice architecture

type MicroService struct {
	name      string
	port      string
	processor *jwt.Processor
	server    *http.Server
}

// Service response structure
type ServiceResponse struct {
	Service   string    `json:"service"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id"`
}

// Health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

func NewMicroService(name, port string) *MicroService {
	// Get secret key from environment variable, or use default value
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
	}

	// Create JWT processor configuration
	config := jwt.Config{
		SecretKey:       secretKey,
		AccessTokenTTL:  1 * time.Hour,  // Inter-service tokens can be slightly longer
		RefreshTokenTTL: 24 * time.Hour, // 24-hour refresh
		Issuer:          name,
		SigningMethod:   jwt.SigningMethodHS256,
	}

	// Microservice internal communication usually doesn't need rate limiting
	config.EnableRateLimit = false

	// Create processor
	processor, err := jwt.NewWithBlacklist(
		secretKey,
		jwt.DefaultBlacklistConfig(),
		config,
	)
	if err != nil {
		log.Fatalf("JWT processor creation failed: %v", err)
	}

	return &MicroService{
		name:      name,
		port:      port,
		processor: processor,
	}
}

func (ms *MicroService) Start() {
	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", ms.healthHandler)
	mux.HandleFunc("/token", ms.tokenHandler)
	mux.HandleFunc("/api/data", ms.authMiddleware(ms.dataHandler))
	mux.HandleFunc("/api/process", ms.authMiddleware(ms.processHandler))
	mux.HandleFunc("/api/call-service", ms.authMiddleware(ms.callServiceHandler))

	// Create HTTP server
	ms.server = &http.Server{
		Addr:         ms.port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		fmt.Printf("🚀 Microservice [%s] started on port %s\n", ms.name, ms.port)
		fmt.Printf("Health check: http://localhost%s/health\n", ms.port)
		fmt.Printf("Get token: http://localhost%s/token\n", ms.port)
		fmt.Printf("API endpoint: http://localhost%s/api/data\n", ms.port)

		if err := ms.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server startup failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	ms.waitForShutdown()
}

func (ms *MicroService) waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Printf("\n🛑 Shutting down microservice [%s]...\n", ms.name)

	// Create shutdown context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully shutdown HTTP server
	if err := ms.server.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown failed: %v", err)
	}

	// Close JWT processor
	if err := ms.processor.Close(); err != nil {
		log.Printf("JWT processor shutdown failed: %v", err)
	}

	fmt.Printf("✅ Microservice [%s] gracefully shut down\n", ms.name)
}

// Health check handler
func (ms *MicroService) healthHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Service:   ms.name,
		Version:   "1.0.0",
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Token generation handler (for inter-service authentication)
func (ms *MicroService) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method supported", http.StatusMethodNotAllowed)
		return
	}

	// Simple service authentication (production should use more secure methods)
	serviceID := r.Header.Get("X-Service-ID")
	serviceSecret := r.Header.Get("X-Service-Secret")

	if serviceID == "" || serviceSecret != "service-secret-123" {
		http.Error(w, "Service authentication failed", http.StatusUnauthorized)
		return
	}

	// Create Claims for inter-service communication
	claims := jwt.Claims{
		UserID:   serviceID,
		Username: serviceID,
		Role:     "service",
		Scopes:   []string{"api:read", "api:write", "service:call"},
		ClientID: serviceID,
		Extra: map[string]any{
			"service_type": "microservice",
			"caller":       ms.name,
		},
	}

	// Generate Token
	token, err := ms.processor.CreateToken(claims)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"token":      token,
		"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		"service":    ms.name,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Data handler
func (ms *MicroService) dataHandler(w http.ResponseWriter, r *http.Request) {
	claimsValue := r.Context().Value("claims")
	if claimsValue == nil {
		http.Error(w, "Unauthorized: User information not found", http.StatusUnauthorized)
		return
	}

	claims, ok := claimsValue.(*jwt.Claims)
	if !ok {
		http.Error(w, "Internal Error: User information format error", http.StatusInternalServerError)
		return
	}

	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = fmt.Sprintf("req_%d", time.Now().UnixNano())
	}

	response := ServiceResponse{
		Service:   ms.name,
		Message:   fmt.Sprintf("Data processing completed, caller: %s", claims.Username),
		Timestamp: time.Now(),
		RequestID: requestID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Process handler
func (ms *MicroService) processHandler(w http.ResponseWriter, r *http.Request) {
	claimsValue := r.Context().Value("claims")
	if claimsValue == nil {
		http.Error(w, "Unauthorized: User information not found", http.StatusUnauthorized)
		return
	}

	claims, ok := claimsValue.(*jwt.Claims)
	if !ok {
		http.Error(w, "Internal Error: User information format error", http.StatusInternalServerError)
		return
	}

	requestID := r.Header.Get("X-Request-ID")

	// Simulate processing time
	time.Sleep(100 * time.Millisecond)

	response := ServiceResponse{
		Service:   ms.name,
		Message:   fmt.Sprintf("Processing completed, user: %s, role: %s", claims.Username, claims.Role),
		Timestamp: time.Now(),
		RequestID: requestID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Inter-service call handler
func (ms *MicroService) callServiceHandler(w http.ResponseWriter, r *http.Request) {
	claimsValue := r.Context().Value("claims")
	if claimsValue == nil {
		http.Error(w, "Unauthorized: User information not found", http.StatusUnauthorized)
		return
	}

	claims, ok := claimsValue.(*jwt.Claims)
	if !ok {
		http.Error(w, "Internal Error: User information format error", http.StatusInternalServerError)
		return
	}

	// Simulate calling other services
	targetService := r.URL.Query().Get("target")
	if targetService == "" {
		targetService = "downstream-service"
	}

	response := map[string]any{
		"service":        ms.name,
		"message":        "Inter-service call successful",
		"caller":         claims.Username,
		"target_service": targetService,
		"timestamp":      time.Now(),
		"call_chain":     []string{ms.name, targetService},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Authentication middleware
func (ms *MicroService) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Token
		token := ms.extractToken(r)
		if token == "" {
			http.Error(w, "Missing authentication token", http.StatusUnauthorized)
			return
		}

		// Validate Token
		claims, valid, err := ms.processor.ValidateToken(token)
		if err != nil || !valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add to context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next(w, r.WithContext(ctx))
	}
}

// Extract Token
func (ms *MicroService) extractToken(r *http.Request) string {
	// Extract from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1]
		}
	}
	return ""
}

func main() {
	// Create and start microservice
	service := NewMicroService("user-service", ":8081")
	service.Start()
}
