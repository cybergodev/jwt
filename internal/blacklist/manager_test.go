package blacklist

import (
	"strings"
	"testing"
	"time"
)

// TestBlacklistTokenString tests the BlacklistTokenString method
func TestBlacklistTokenString(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)
	defer manager.Close()

	tests := []struct {
		name        string
		tokenString string
		wantError   bool
		errorMsg    string
	}{
		{
			name:        "empty token string",
			tokenString: "",
			wantError:   true,
			errorMsg:    "token string cannot be empty",
		},
		{
			name:        "invalid token format",
			tokenString: "invalid",
			wantError:   true,
			errorMsg:    "failed to parse token",
		},
		{
			name:        "token without jti",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "token does not contain a valid ID",
		},
		{
			name:        "valid token with jti and exp",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0b2tfMTIzNDU2IiwiZXhwIjoxNzAwMDAwMDAwfQ.signature",
			wantError:   false,
		},
		{
			name:        "valid token with jti without exp",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0b2tfNzg5MDEyIn0.signature",
			wantError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.BlacklistTokenString(tt.tokenString)
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

// TestBlacklistTokenEdgeCases tests edge cases in BlacklistToken
func TestBlacklistTokenEdgeCases(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)
	defer manager.Close()

	// Test with empty token ID
	err := manager.BlacklistToken("", time.Now().Add(time.Hour))
	if err == nil {
		t.Error("Expected error for empty token ID")
	}
	if !strings.Contains(err.Error(), "token ID cannot be empty") {
		t.Errorf("Expected 'token ID cannot be empty' error, got %v", err)
	}

	// Test with valid token ID
	err = manager.BlacklistToken("tok_valid123", time.Now().Add(time.Hour))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify token is blacklisted
	isBlacklisted, err := manager.IsBlacklisted("tok_valid123")
	if err != nil {
		t.Errorf("Failed to check blacklist: %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted")
	}
}

// TestIsBlacklistedEdgeCases tests edge cases in IsBlacklisted
func TestIsBlacklistedEdgeCases(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)
	defer manager.Close()

	// Test with empty token ID
	isBlacklisted, err := manager.IsBlacklisted("")
	if err != nil {
		t.Errorf("Expected no error for empty token ID, got %v", err)
	}
	if isBlacklisted {
		t.Error("Empty token ID should not be blacklisted")
	}

	// Test with non-existent token ID
	isBlacklisted, err = manager.IsBlacklisted("tok_nonexistent")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if isBlacklisted {
		t.Error("Non-existent token should not be blacklisted")
	}
}

// TestManagerCloseWithTokens tests manager close with active tokens
func TestManagerCloseWithTokens(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)

	// Add some tokens
	err := manager.BlacklistToken("tok_test1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to blacklist token: %v", err)
	}

	// Close manager
	err = manager.Close()
	if err != nil {
		t.Errorf("Failed to close manager: %v", err)
	}
}

// TestBlacklistTokenStringWithExpiration tests token blacklisting with different expiration scenarios
func TestBlacklistTokenStringWithExpiration(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)
	defer manager.Close()

	// Token with zero expiration (should use default 24h)
	// {"typ":"JWT","alg":"HS256"}.{"jti":"tok_noexp"}
	tokenNoExp := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0b2tfbm9leHAifQ.signature"

	err := manager.BlacklistTokenString(tokenNoExp)
	if err != nil {
		t.Errorf("Failed to blacklist token without expiration: %v", err)
	}

	// Verify token is blacklisted (check immediately after adding)
	isBlacklisted, err := manager.IsBlacklisted("tok_noexp")
	if err != nil {
		t.Errorf("Failed to check blacklist: %v", err)
	}
	if !isBlacklisted {
		t.Error("Token without expiration should be blacklisted")
	}

	// Token with future expiration (year 2033)
	// {"typ":"JWT","alg":"HS256"}.{"jti":"tok_future","exp":2000000000}
	tokenWithExp := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0b2tfZnV0dXJlIiwiZXhwIjoyMDAwMDAwMDAwfQ.signature"

	err = manager.BlacklistTokenString(tokenWithExp)
	if err != nil {
		t.Errorf("Failed to blacklist token with expiration: %v", err)
	}

	// Verify token is blacklisted
	isBlacklisted, err = manager.IsBlacklisted("tok_future")
	if err != nil {
		t.Errorf("Failed to check blacklist: %v", err)
	}
	if !isBlacklisted {
		t.Error("Token with future expiration should be blacklisted")
	}
}
