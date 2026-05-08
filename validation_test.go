package jwt

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidationClaimsEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	tests := []struct {
		name      string
		claims    Claims
		wantError bool
	}{
		{"control characters in UserID", Claims{UserID: "user\x00id", Username: "testuser"}, true},
		{"tab character allowed", Claims{UserID: "user\tid", Username: "testuser"}, false},
		{"newline allowed", Claims{UserID: "user\nid", Username: "testuser"}, false},
		{"carriage return allowed", Claims{UserID: "user\rid", Username: "testuser"}, false},
		{"too many permissions", Claims{UserID: "user1", Username: "testuser", Permissions: make([]string, 101)}, true},
		{"too many scopes", Claims{UserID: "user1", Username: "testuser", Scopes: make([]string, 101)}, true},
		{"too many audience", Claims{UserID: "user1", Username: "testuser", RegisteredClaims: RegisteredClaims{Audience: make([]string, 101)}}, true},
		{"too many extra fields", Claims{UserID: "user1", Username: "testuser", Extra: makeMapWithNFields(51)}, true},
		{"max allowed extra fields", Claims{UserID: "user1", Username: "testuser", Extra: makeMapWithNFields(50)}, false},
		{"nested map in extra", Claims{UserID: "user1", Username: "testuser", Extra: map[string]any{"nested": map[string]any{"key": "value"}}}, true},
		{"string array in extra", Claims{UserID: "user1", Username: "testuser", Extra: map[string]any{"tags": []string{"tag1", "tag2"}}}, false},
		{"too long extra key", Claims{UserID: "user1", Username: "testuser", Extra: map[string]any{strings.Repeat("a", 257): "value"}}, true},
		{"too long extra value", Claims{UserID: "user1", Username: "testuser", Extra: map[string]any{"key": strings.Repeat("a", 257)}}, true},
		{"unsupported extra type int", Claims{UserID: "user1", Username: "testuser", Extra: map[string]any{"key": 12345}}, true},
		{"unsupported extra type bool", Claims{UserID: "user1", Username: "testuser", Extra: map[string]any{"key": true}}, true},
		{"unsupported extra type float", Claims{UserID: "user1", Username: "testuser", Extra: map[string]any{"key": 3.14}}, true},
		{"too long permission item", Claims{UserID: "user1", Username: "testuser", Permissions: []string{strings.Repeat("a", 257)}}, true},
		{"too long scope item", Claims{UserID: "user1", Username: "testuser", Scopes: []string{strings.Repeat("a", 257)}}, true},
		{"too long audience item", Claims{UserID: "user1", Username: "testuser", RegisteredClaims: RegisteredClaims{Audience: []string{strings.Repeat("a", 257)}}}, true},
		{"dangerous permission item", Claims{UserID: "user1", Username: "testuser", Permissions: []string{"<script>alert(1)</script>"}}, true},
		{"dangerous scope item", Claims{UserID: "user1", Username: "testuser", Scopes: []string{"javascript:alert(1)"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.Create(&tt.claims)
			if tt.wantError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestControlCharDetection(t *testing.T) {
	tests := []struct {
		name   string
		char   byte
		isCtrl bool
	}{
		{"null byte", 0x00, true},
		{"SOH", 0x01, true},
		{"ETX", 0x02, true},
		{"US", 0x1F, true},
		{"BS", 0x08, true},
		{"RS", 0x1E, true},
		{"tab (allowed)", 0x09, false},
		{"newline (allowed)", 0x0A, false},
		{"carriage return (allowed)", 0x0D, false},
		{"space", 0x20, false},
		{"tilde", 0x7E, false},
		{"DEL", 0x7F, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isControlChar(tt.char) != tt.isCtrl {
				t.Errorf("isControlChar(0x%02X) = %v, want %v", tt.char, !tt.isCtrl, tt.isCtrl)
			}
		})
	}
}

func TestValidateStringArray(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		err   bool
	}{
		{"nil slice", nil, false},
		{"empty slice", []string{}, false},
		{"valid slice", []string{"read", "write"}, false},
		{"too many items", make([]string, 101), true},
		{"item with control char", []string{"read\x00write"}, true},
		{"item too long", []string{strings.Repeat("a", 257)}, true},
		{"item with script tag", []string{"<script>"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStringArray("test_field", tt.items)
			if tt.err && err == nil {
				t.Error("Expected error")
			}
			if !tt.err && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func makeMapWithNFields(n int) map[string]any {
	m := make(map[string]any, n)
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("key%d", i)] = "value"
	}
	return m
}
