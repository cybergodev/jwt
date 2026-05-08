package jwt

import (
	"errors"
	"testing"
	"time"
)

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

// testMockStore is a mock BlacklistStore for testing.
type testMockStore struct {
	tokens map[string]time.Time
}

func newTestMockStore() *testMockStore {
	return &testMockStore{tokens: make(map[string]time.Time)}
}

func (m *testMockStore) Add(tokenID string, expiresAt time.Time) error {
	m.tokens[tokenID] = expiresAt
	return nil
}

func (m *testMockStore) Contains(tokenID string) (bool, error) {
	exp, exists := m.tokens[tokenID]
	if !exists {
		return false, nil
	}
	return time.Now().Before(exp), nil
}

func (m *testMockStore) Close() error {
	return nil
}

func TestGenericCreateAndValidateToken(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := &TestCustomClaims{
		UserID:  "user123",
		Email:   "test@example.com",
		IsAdmin: true,
		TeamID:  "team1",
	}

	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}
	if token == "" {
		t.Fatal("Token should not be empty")
	}

	validatedClaims := &TestCustomClaims{}
	result, valid, err := processor.ValidateInto(token, validatedClaims)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if !valid {
		t.Fatal("Token should be valid")
	}

	resultClaims := result.(*TestCustomClaims)
	if resultClaims.UserID != claims.UserID {
		t.Errorf("UserID: got %s, want %s", resultClaims.UserID, claims.UserID)
	}
	if resultClaims.Email != claims.Email {
		t.Errorf("Email: got %s, want %s", resultClaims.Email, claims.Email)
	}
	if resultClaims.IsAdmin != claims.IsAdmin {
		t.Errorf("IsAdmin: got %v, want %v", resultClaims.IsAdmin, claims.IsAdmin)
	}
	if resultClaims.TeamID != claims.TeamID {
		t.Errorf("TeamID: got %s, want %s", resultClaims.TeamID, claims.TeamID)
	}
}

func TestGenericCreateRefreshToken(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := &TestCustomClaims{UserID: "user123", Email: "test@example.com"}
	token, err := processor.CreateRefresh(claims)
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateInto(token, validatedClaims)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}
	if !valid {
		t.Fatal("Refresh token should be valid")
	}
}

func TestGenericInvalidClaims(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	tests := []struct {
		name   string
		claims *TestCustomClaims
	}{
		{"missing UserID and Email", &TestCustomClaims{}},
		{"missing Email only", &TestCustomClaims{UserID: "user1"}},
		{"missing UserID only", &TestCustomClaims{Email: "test@example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.Create(tt.claims)
			if err == nil {
				t.Error("Expected error for invalid claims")
			}
		})
	}
}

func TestGenericParseUnverified(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := &TestCustomClaims{UserID: "user000", Email: "parse@example.com"}
	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims := &TestCustomClaims{}
	if err := processor.ParseUnverified(token, parsedClaims); err != nil {
		t.Fatalf("Failed to parse token unverified: %v", err)
	}
	if parsedClaims.UserID != claims.UserID {
		t.Errorf("UserID: got %s, want %s", parsedClaims.UserID, claims.UserID)
	}
}

func TestGenericClaimsImplementsInterface(t *testing.T) {
	var _ CustomClaims = (*Claims)(nil)
	var _ CustomClaims = (*TestCustomClaims)(nil)

	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := &Claims{UserID: "standard-user", Username: "standard-username", Role: "admin"}
	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Failed to create token with standard Claims: %v", err)
	}

	validatedClaims := &Claims{}
	result, valid, err := processor.ValidateInto(token, validatedClaims)
	if err != nil || !valid {
		t.Fatalf("Failed to validate token: valid=%v, err=%v", valid, err)
	}

	resultClaims := result.(*Claims)
	if resultClaims.UserID != claims.UserID {
		t.Errorf("UserID: got %s, want %s", resultClaims.UserID, claims.UserID)
	}
}

func TestGenericExpiredToken(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := &TestCustomClaims{
		UserID: "expired-user",
		Email:  "expired@example.com",
		RegisteredClaims: RegisteredClaims{
			ExpiresAt: NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}

	token, err := createTokenWithCustomClaims(processor, claims, time.Hour, TokenTypeAccess)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateInto(token, validatedClaims)
	if valid {
		t.Fatal("Expired token should not be valid")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestGenericCustomStore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = BlacklistConfig{Store: newTestMockStore()}

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor with custom store: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := &TestCustomClaims{UserID: "store-user", Email: "store@example.com"}
	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateInto(token, validatedClaims)
	if err != nil || !valid {
		t.Fatalf("Token should be valid with custom store: %v", err)
	}
}
