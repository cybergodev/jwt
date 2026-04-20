package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const genericTestSecretKey = "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"

// CustomClaims for testing
type TestCustomClaims struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	IsAdmin bool   `json:"is_admin"`
	TeamID  string `json:"team_id,omitempty"`
	RegisteredClaims
}

func (c *TestCustomClaims) GetRegisteredClaims() *RegisteredClaims {
	return &c.RegisteredClaims
}

func (c *TestCustomClaims) Validate() error {
	if c.UserID == "" {
		return ErrInvalidClaims
	}
	if c.Email == "" {
		return ErrInvalidClaims
	}
	return nil
}

func TestGenericCreateAndValidateToken(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID:  "user123",
		Email:   "test@example.com",
		IsAdmin: true,
		TeamID:  "team1",
	}

	// Create token
	token, err := processor.CreateTokenWith(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if token == "" {
		t.Fatal("Token should not be empty")
	}

	// Validate token
	validatedClaims := &TestCustomClaims{}
	result, valid, err := processor.ValidateTokenFor(token, validatedClaims)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Fatal("Token should be valid")
	}

	resultClaims, ok := result.(*TestCustomClaims)
	if !ok {
		t.Fatal("Expected TestCustomClaims type")
	}

	if resultClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID %s, got %s", claims.UserID, resultClaims.UserID)
	}

	if resultClaims.Email != claims.Email {
		t.Errorf("Expected Email %s, got %s", claims.Email, resultClaims.Email)
	}

	if resultClaims.IsAdmin != claims.IsAdmin {
		t.Errorf("Expected IsAdmin %v, got %v", claims.IsAdmin, resultClaims.IsAdmin)
	}

	if resultClaims.TeamID != claims.TeamID {
		t.Errorf("Expected TeamID %s, got %s", claims.TeamID, resultClaims.TeamID)
	}
}

func TestGenericCreateRefreshToken(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID: "user123",
		Email:  "test@example.com",
	}

	token, err := processor.CreateRefreshTokenWith(claims)
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	if token == "" {
		t.Fatal("Token should not be empty")
	}

	// Validate the refresh token
	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateTokenFor(token, validatedClaims)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}

	if !valid {
		t.Fatal("Refresh token should be valid")
	}
}

func TestGenericInvalidClaims(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Claims without required fields
	claims := &TestCustomClaims{
		UserID: "", // Missing UserID
		Email:  "", // Missing Email
	}

	_, err = processor.CreateTokenWith(claims)
	if err == nil {
		t.Fatal("Expected error for invalid claims")
	}
}

func TestGenericTokenRevocation(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID: "user789",
		Email:  "revoke@example.com",
	}

	// Create token
	token, err := processor.CreateTokenWith(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Validate should work
	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateTokenFor(token, validatedClaims)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if !valid {
		t.Fatal("Token should be valid before revocation")
	}

	// Revoke token
	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Validate should fail now
	validatedClaims2 := &TestCustomClaims{}
	_, valid, err = processor.ValidateTokenFor(token, validatedClaims2)
	if err != ErrTokenRevoked {
		t.Fatalf("Expected ErrTokenRevoked, got: %v", err)
	}
	if valid {
		t.Fatal("Token should not be valid after revocation")
	}
}

func TestGenericParseUnverified(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID: "user000",
		Email:  "parse@example.com",
	}

	token, err := processor.CreateTokenWith(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Parse without verification
	parsedClaims := &TestCustomClaims{}
	err = processor.ParseUnverified(token, parsedClaims)
	if err != nil {
		t.Fatalf("Failed to parse token unverified: %v", err)
	}

	if parsedClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID %s, got %s", claims.UserID, parsedClaims.UserID)
	}
}

func TestGenericClosedProcessor(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Close processor
	processor.Close()

	claims := &TestCustomClaims{
		UserID: "user999",
		Email:  "closed@example.com",
	}

	// All operations should fail
	_, err = processor.CreateTokenWith(claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}

	_, _, err = processor.ValidateTokenFor("some-token", claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}

	_, err = processor.CreateRefreshTokenWith(claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}
}

func TestGenericClaimsImplementsInterface(t *testing.T) {
	// Verify that Claims implements CustomClaims
	var _ CustomClaims = (*Claims)(nil)

	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Use standard Claims with generic functions
	claims := &Claims{
		UserID:   "standard-user",
		Username: "standard-username",
		Role:     "admin",
	}

	token, err := processor.CreateTokenWith(claims)
	if err != nil {
		t.Fatalf("Failed to create token with standard Claims: %v", err)
	}

	validatedClaims := &Claims{}
	result, valid, err := processor.ValidateTokenFor(token, validatedClaims)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Fatal("Token should be valid")
	}

	resultClaims, ok := result.(*Claims)
	if !ok {
		t.Fatal("Expected Claims type")
	}

	if resultClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID %s, got %s", claims.UserID, resultClaims.UserID)
	}
}

func TestGenericExpiredToken(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create claims with already expired time
	claims := &TestCustomClaims{
		UserID: "expired-user",
		Email:  "expired@example.com",
		RegisteredClaims: RegisteredClaims{
			ExpiresAt: NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}

	token, err := createTokenWithCustomClaims(processor, claims, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Validate should fail
	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateTokenFor(token, validatedClaims)

	if valid {
		t.Fatal("Expired token should not be valid")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestGenericCustomStore(t *testing.T) {
	// Create a mock store
	mockStore := &mockBlacklistStore{
		tokens: make(map[string]time.Time),
	}

	cfg := DefaultConfig()
	cfg.SecretKey = genericTestSecretKey
	cfg.Blacklist = BlacklistConfig{
		Store: mockStore,
	}
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor with custom store: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{
		UserID: "store-user",
		Email:  "store@example.com",
	}

	token, err := processor.CreateTokenWith(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateTokenFor(token, validatedClaims)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Fatal("Token should be valid with custom store")
	}
}

func TestCreateTokenWithDeepValidation(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	maliciousClaims := []struct {
		name   string
		claims *Claims
	}{
		{"XSS via CreateTokenWith", &Claims{UserID: "<script>alert('xss')</script>", Username: "test"}},
		{"JavaScript injection via CreateTokenWith", &Claims{UserID: "test", Username: "javascript:alert(1)"}},
		{"Path traversal via CreateTokenWith", &Claims{UserID: "../../../etc/passwd", Username: "test"}},
		{"Too long field via CreateTokenWith", &Claims{UserID: "test", Username: strings.Repeat("a", 1000)}},
	}

	for _, tt := range maliciousClaims {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.CreateTokenWith(tt.claims)
			if err == nil {
				t.Errorf("CreateTokenWith should reject malicious claims: %s", tt.name)
			}
		})
	}
}

func TestCreateRefreshTokenWithDeepValidation(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &Claims{UserID: "<script>alert('xss')</script>", Username: "test"}
	_, err = processor.CreateRefreshTokenWith(claims)
	if err == nil {
		t.Error("CreateRefreshTokenWith should reject dangerous patterns in *Claims")
	}
}

func TestCreateTokenWithCustomClaimsNoDeepValidation(t *testing.T) {
	processor, err := newTestProcessor(genericTestSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Custom claims types only run their own Validate() — no deep pattern check
	claims := &TestCustomClaims{
		UserID: "user-with-<script>tag",
		Email:  "test@example.com",
	}
	_, err = processor.CreateTokenWith(claims)
	if err != nil {
		t.Errorf("Custom claims should not trigger deep validation: %v", err)
	}
}

// Mock blacklist store for testing
type mockBlacklistStore struct {
	tokens map[string]time.Time
}

func (m *mockBlacklistStore) Add(tokenID string, expiresAt time.Time) error {
	m.tokens[tokenID] = expiresAt
	return nil
}

func (m *mockBlacklistStore) Contains(tokenID string) (bool, error) {
	exp, exists := m.tokens[tokenID]
	if !exists {
		return false, nil
	}
	return time.Now().Before(exp), nil
}

func (m *mockBlacklistStore) Cleanup() (int, error) {
	return 0, nil
}

func (m *mockBlacklistStore) Close() error {
	return nil
}
