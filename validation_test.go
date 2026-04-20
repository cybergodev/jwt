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

// Note: Dangerous pattern detection tests consolidated into security_test.go

// Note: String/array validation tested via TestValidationClaimsEdgeCases

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

// Note: ParseUnverified edge cases tested in coverage_test.go

