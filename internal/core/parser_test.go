package core

import (
	"strings"
	"testing"

	"github.com/cybergodev/jwt/internal/signing"
)

// TestParseWithClaimsErrorPaths tests error paths in ParseWithClaims
func TestParseWithClaimsErrorPaths(t *testing.T) {
	type testClaims struct {
		UserID string `json:"user_id"`
	}

	tests := []struct {
		name        string
		tokenString string
		wantError   bool
		errorMsg    string
	}{
		{
			name:        "empty token",
			tokenString: "",
			wantError:   true,
			errorMsg:    "empty token",
		},
		{
			name:        "token too large",
			tokenString: strings.Repeat("a", 8193),
			wantError:   true,
			errorMsg:    "token too large",
		},
		{
			name:        "invalid format - no dots",
			tokenString: "invalidtoken",
			wantError:   true,
			errorMsg:    "invalid token format",
		},
		{
			name:        "invalid format - one dot",
			tokenString: "invalid.token",
			wantError:   true,
			errorMsg:    "invalid token format",
		},
		{
			name:        "invalid header encoding",
			tokenString: "!!!invalid!!!.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "failed to decode header",
		},
		{
			name:        "missing algorithm",
			tokenString: "eyJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "empty algorithm",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiIifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "insecure algorithm - NONE",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "insecure algorithm - NULL",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJOVUxMIn0.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "insecure algorithm - PLAIN",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJQTEFJTiJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "insecure algorithm - HS1",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzEifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "insecure algorithm - RS1",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzEifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "insecure algorithm - ES1",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzEifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "insecure algorithm - HS224",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzIyNCJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "invalid or insecure algorithm",
		},
		{
			name:        "unsupported algorithm",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "unsupported signing method",
		},
		{
			name:        "invalid claims encoding",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.!!!invalid!!!.signature",
			wantError:   true,
			errorMsg:    "failed to decode claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &testClaims{}
			keyFunc := func(token *Core) (any, error) {
				return []byte("test-secret-key"), nil
			}

			_, err := ParseWithClaims(tt.tokenString, claims, keyFunc)
			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if tt.wantError && err != nil && !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("Expected error containing '%s', got '%v'", tt.errorMsg, err)
			}
		})
	}
}

// TestParseUnverifiedErrorPaths tests error paths in ParseUnverified
func TestParseUnverifiedErrorPaths(t *testing.T) {
	type testClaims struct {
		UserID string `json:"user_id"`
	}

	tests := []struct {
		name        string
		tokenString string
		wantError   bool
		errorMsg    string
	}{
		{
			name:        "empty token",
			tokenString: "",
			wantError:   true,
			errorMsg:    "empty token",
		},
		{
			name:        "token too large",
			tokenString: strings.Repeat("a", 8193),
			wantError:   true,
			errorMsg:    "token too large",
		},
		{
			name:        "invalid format",
			tokenString: "invalid",
			wantError:   true,
			errorMsg:    "invalid token format",
		},
		{
			name:        "invalid header",
			tokenString: "!!!invalid!!!.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "failed to decode header",
		},
		{
			name:        "insecure algorithm in header",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "insecure algorithm detected",
		},
		{
			name:        "invalid claims",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.!!!invalid!!!.signature",
			wantError:   true,
			errorMsg:    "failed to decode claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &testClaims{}
			_, _, err := ParseUnverified(tt.tokenString, claims)
			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if tt.wantError && err != nil && !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("Expected error containing '%s', got '%v'", tt.errorMsg, err)
			}
		})
	}
}

// TestIsInsecureAlgorithmAdditional tests additional insecure algorithm variations
func TestIsInsecureAlgorithmAdditional(t *testing.T) {
	tests := []struct {
		alg      string
		insecure bool
	}{
		{"  NONE  ", true}, // with whitespace
		{"  null  ", true},
		{"  PLAIN  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			result := isInsecureAlgorithm(tt.alg)
			if result != tt.insecure {
				t.Errorf("isInsecureAlgorithm(%q) = %v, want %v", tt.alg, result, tt.insecure)
			}
		})
	}
}

// TestParseWithClaimsKeyFuncError tests key function error handling
func TestParseWithClaimsKeyFuncError(t *testing.T) {
	// Create a valid token first
	method := signing.GetHMACMethod("HS256")
	claims := map[string]any{
		"user_id": "test",
	}
	token := NewTokenWithClaims(method, claims)
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Parse with key function that returns error
	keyFunc := func(token *Core) (any, error) {
		return nil, ErrTestKeyFunc
	}

	parsedClaims := make(map[string]any)
	_, err = ParseWithClaims(tokenString, &parsedClaims, keyFunc)
	if err == nil {
		t.Error("Expected error from key function")
	}
	if !strings.Contains(err.Error(), "failed to get key") {
		t.Errorf("Expected 'failed to get key' error, got %v", err)
	}
}

var ErrTestKeyFunc = &testError{msg: "test key function error"}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestParseWithClaimsInvalidSignature tests signature verification failure
func TestParseWithClaimsInvalidSignature(t *testing.T) {
	// Create a valid token
	method := signing.GetHMACMethod("HS256")
	claims := map[string]any{
		"user_id": "test",
	}
	token := NewTokenWithClaims(method, claims)
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Parse with different key (signature verification should fail)
	wrongKey := []byte("wrong-secret-key-with-sufficient-length-32bytes")
	keyFunc := func(token *Core) (any, error) {
		return wrongKey, nil
	}

	parsedClaims := make(map[string]any)
	parsedToken, err := ParseWithClaims(tokenString, &parsedClaims, keyFunc)
	if err != nil {
		t.Fatalf("Parse should not return error, got %v", err)
	}

	if parsedToken.Valid {
		t.Error("Token should not be valid with wrong key")
	}
}
