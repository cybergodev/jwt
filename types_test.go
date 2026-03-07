package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

// ============================================================================
// TYPES TESTS - Tests for types.go
// Note: testSecretKey and newTestProcessor are defined in jwt_test.go
// ============================================================================

// TestNumericDateMarshalJSON tests JSON marshaling of NumericDate
func TestNumericDateMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		date     NumericDate
		expected string
	}{
		{
			name:     "zero time returns null",
			date:     NumericDate{},
			expected: "null",
		},
		{
			name:     "valid timestamp",
			date:     NewNumericDate(time.Unix(1609459200, 0)),
			expected: "1609459200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must marshal pointer for MarshalJSON to be called (pointer receiver)
			data, err := json.Marshal(&tt.date)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			if string(data) != tt.expected {
				t.Errorf("Marshal() = %s, want %s", string(data), tt.expected)
			}
		})
	}
}

// TestNumericDateUnmarshalJSON tests JSON unmarshaling of NumericDate
func TestNumericDateUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantUnix  int64
		wantZero  bool
		wantError bool
	}{
		{
			name:     "valid timestamp",
			input:    "1609459200",
			wantUnix: 1609459200,
		},
		{
			name:     "null value",
			input:    "null",
			wantZero: true,
		},
		{
			name:     "empty string",
			input:    `""`,
			wantZero: true,
		},
		{
			name:     "quoted timestamp",
			input:    `"1609459200"`,
			wantUnix: 1609459200,
		},
		{
			name:      "invalid format",
			input:     `"not-a-number"`,
			wantError: true,
		},
		{
			name:      "negative timestamp",
			input:     "-1",
			wantError: true,
		},
		{
			name:      "exceeds max timestamp",
			input:     "999999999999",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nd NumericDate
			err := json.Unmarshal([]byte(tt.input), &nd)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.wantZero {
				if !nd.Time.IsZero() {
					t.Error("Expected zero time")
				}
			} else {
				if nd.Unix() != tt.wantUnix {
					t.Errorf("Unix() = %d, want %d", nd.Unix(), tt.wantUnix)
				}
			}
		})
	}
}

// TestNumericDateEdgeCases tests edge cases for NumericDate
func TestNumericDateEdgeCases(t *testing.T) {
	// Test zero time
	zeroDate := NumericDate{}
	data, err := json.Marshal(&zeroDate)
	if err != nil {
		t.Fatalf("Failed to marshal zero time: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("Zero time should marshal to null, got %s", string(data))
	}

	// Test negative timestamp (should return null)
	negativeDate := NumericDate{Time: time.Unix(-100, 0)}
	data, err = json.Marshal(&negativeDate)
	if err != nil {
		t.Fatalf("Failed to marshal negative time: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("Negative time should marshal to null, got %s", string(data))
	}

	// Test extremely large timestamp (should return null)
	largeDate := NumericDate{Time: time.Unix(999999999999, 0)}
	data, err = json.Marshal(&largeDate)
	if err != nil {
		t.Fatalf("Failed to marshal large time: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("Large time should marshal to null, got %s", string(data))
	}
}

// TestClaimsValidationBasic tests claims validation
func TestClaimsValidationBasic(t *testing.T) {
	secretKey := "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024"
	processor, err := newTestProcessor(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Both UserID and Username empty should fail
	claims := Claims{}
	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Expected error for empty UserID and Username")
	}
}

// TestRegisteredClaimsFields tests RegisteredClaims fields
func TestRegisteredClaimsFields(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "test_user",
		Username: "test",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.ValidateToken(token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}

	// Verify registered claims are set
	if parsedClaims.IssuedAt.IsZero() {
		t.Error("IssuedAt should be set automatically")
	}
	if parsedClaims.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set automatically")
	}
	if parsedClaims.ID == "" {
		t.Error("ID (jti) should be set automatically")
	}
}

// TestSigningMethodConstants tests signing method constants
func TestSigningMethodConstants(t *testing.T) {
	methods := []SigningMethod{
		SigningMethodHS256,
		SigningMethodHS384,
		SigningMethodHS512,
		SigningMethodRS256,
		SigningMethodRS384,
		SigningMethodRS512,
		SigningMethodES256,
		SigningMethodES384,
		SigningMethodES512,
	}

	expected := []string{
		"HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
	}

	for i, method := range methods {
		if string(method) != expected[i] {
			t.Errorf("SigningMethod %s != %s", method, expected[i])
		}
	}
}
