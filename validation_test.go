package jwt

import (
	"strings"
	"testing"
)

// ============================================================================
// VALIDATION TESTS - Tests for validation.go
// Functions renamed to avoid conflicts with existing tests
// ============================================================================

// TestValidationClaimsEdgeCases tests validation edge cases for claims
func TestValidationClaimsEdgeCases(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		claims    Claims
		wantError bool
	}{
		{
			name: "claims with control characters",
			claims: Claims{
				UserID:   "user\x00id",
				Username: "testuser",
			},
			wantError: true,
		},
		{
			name: "claims with tab character (allowed)",
			claims: Claims{
				UserID:   "user\tid",
				Username: "testuser",
			},
			wantError: false,
		},
		{
			name: "claims with newline (allowed)",
			claims: Claims{
				UserID:   "user\nid",
				Username: "testuser",
			},
			wantError: false,
		},
		{
			name: "claims with carriage return (allowed)",
			claims: Claims{
				UserID:   "user\rid",
				Username: "testuser",
			},
			wantError: false,
		},
		{
			name: "claims with too many permissions",
			claims: Claims{
				UserID:      "user1",
				Username:    "testuser",
				Permissions: make([]string, 101),
			},
			wantError: true,
		},
		{
			name: "claims with too many scopes",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Scopes:   make([]string, 101),
			},
			wantError: true,
		},
		{
			name: "claims with too many audience",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				RegisteredClaims: RegisteredClaims{
					Audience: make([]string, 101),
				},
			},
			wantError: true,
		},
		{
			name: "claims with too many extra fields",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra:    make(map[string]any, 51),
			},
			wantError: true,
		},
		{
			name: "claims with nested map in extra",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					"nested": map[string]any{"key": "value"},
				},
			},
			wantError: true,
		},
		{
			name: "claims with string array in extra",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					"tags": []string{"tag1", "tag2"},
				},
			},
			wantError: false,
		},
		{
			name: "claims with too long extra key",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					strings.Repeat("a", 257): "value",
				},
			},
			wantError: true,
		},
		{
			name: "claims with too long extra value",
			claims: Claims{
				UserID:   "user1",
				Username: "testuser",
				Extra: map[string]any{
					"key": strings.Repeat("a", 257),
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Populate extra fields if needed
			if tt.name == "claims with too many extra fields" {
				for i := 0; i < 51; i++ {
					tt.claims.Extra[string(rune('a'+i%26))+string(rune(i))] = "value"
				}
			}

			_, err := processor.CreateToken(tt.claims)
			if tt.wantError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestDangerousPatternDetectionAll tests all dangerous patterns
func TestDangerousPatternDetectionAll(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	dangerousPatterns := []string{
		"<script>alert('xss')</script>",
		"javascript:alert('xss')",
		"data:text/html,<script>alert('xss')</script>",
		"eval(malicious_code)",
		"../../../etc/passwd",
		"file:///etc/passwd",
		"vbscript:msgbox('xss')",
		"<SCRIPT>alert('xss')</SCRIPT>",
		"JaVaScRiPt:alert('xss')",
	}

	for _, pattern := range dangerousPatterns {
		t.Run("pattern_"+pattern[:min(10, len(pattern))], func(t *testing.T) {
			claims := Claims{
				UserID:   pattern,
				Username: "testuser",
			}
			_, err := processor.CreateToken(claims)
			if err == nil {
				t.Errorf("Expected error for dangerous pattern: %s", pattern)
			}
		})
	}
}

// TestValidateStringArray tests validateStringArray function
func TestValidateStringArray(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test valid permissions
	claims := Claims{
		UserID:      "user1",
		Username:    "test",
		Permissions: []string{"read", "write", "delete"},
	}
	_, err = processor.CreateToken(claims)
	if err != nil {
		t.Errorf("Valid permissions should work: %v", err)
	}

	// Test empty permissions
	claims = Claims{
		UserID:      "user2",
		Username:    "test",
		Permissions: []string{},
	}
	_, err = processor.CreateToken(claims)
	if err != nil {
		t.Errorf("Empty permissions should work: %v", err)
	}

	// Test too many permissions
	tooManyPerms := make([]string, 101)
	for i := range tooManyPerms {
		tooManyPerms[i] = "perm"
	}
	claims = Claims{
		UserID:      "user3",
		Username:    "test",
		Permissions: tooManyPerms,
	}
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Too many permissions should fail")
	}

	// Test permission with dangerous pattern
	claims = Claims{
		UserID:      "user4",
		Username:    "test",
		Permissions: []string{"<script>alert(1)</script>"},
	}
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Dangerous pattern in permissions should fail")
	}
}

// TestValidateString tests string validation
func TestValidateString(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		userID    string
		username  string
		wantError bool
	}{
		{
			name:      "normal values",
			userID:    "user123",
			username:  "testuser",
			wantError: false,
		},
		{
			name:      "empty values",
			userID:    "",
			username:  "",
			wantError: true,
		},
		{
			name:      "max length",
			userID:    strings.Repeat("a", 256),
			username:  "test",
			wantError: false,
		},
		{
			name:      "exceeds max length",
			userID:    strings.Repeat("a", 257),
			username:  "test",
			wantError: true,
		},
		{
			name:      "control character",
			userID:    "user\x01id",
			username:  "test",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := Claims{
				UserID:   tt.userID,
				Username: tt.username,
			}
			_, err := processor.CreateToken(claims)
			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestControlCharDetection tests control character detection
func TestControlCharDetection(t *testing.T) {
	// Test invalid control characters (0x00-0x1F, excluding tab/newline/CR)
	invalidChars := []byte{0x00, 0x01, 0x02, 0x1F, 0x08, 0x1E}
	for _, c := range invalidChars {
		if !isControlChar(c) {
			t.Errorf("Character 0x%02X should be detected as control char", c)
		}
	}

	// Test valid control characters (tab, newline, carriage return)
	validChars := []byte{0x09, 0x0A, 0x0D} // tab, newline, carriage return
	for _, c := range validChars {
		if isControlChar(c) {
			t.Errorf("Character 0x%02X should not be detected as control char", c)
		}
	}

	// Test printable characters (0x20-0x7E)
	for c := byte(0x20); c < 0x7F; c++ {
		if isControlChar(c) {
			t.Errorf("Printable character 0x%02X should not be detected as control char", c)
		}
	}
}

// TestParseUnverifiedTokenEdgeCases tests ParseUnverified edge cases
func TestParseUnverifiedTokenEdgeCases(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "empty token",
			token:     "",
			wantError: true,
		},
		{
			name:      "malformed token - no dots",
			token:     "notavalidtoken",
			wantError: true,
		},
		{
			name:      "malformed token - one dot",
			token:     "only.one",
			wantError: true,
		},
		{
			name:      "malformed token - too many dots",
			token:     "too.many.dots.here",
			wantError: true,
		},
		{
			name:      "invalid base64",
			token:     "invalid!base64.validpart",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.IsTokenRevoked(tt.token)
			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
