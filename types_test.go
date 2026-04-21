package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNumericDateMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		date     NumericDate
		expected string
	}{
		{"zero time returns null", NumericDate{}, "null"},
		{"valid timestamp", NewNumericDate(time.Unix(1609459200, 0)), "1609459200"},
		{"negative timestamp returns null", NumericDate{Time: time.Unix(-100, 0)}, "null"},
		{"large timestamp returns null", NumericDate{Time: time.Unix(999999999999, 0)}, "null"},
		{"max valid timestamp", NewNumericDate(time.Unix(253402300799, 0)), "253402300799"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestNumericDateUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantUnix  int64
		wantZero  bool
		wantError bool
	}{
		{"valid timestamp", "1609459200", 1609459200, false, false},
		{"null value", "null", 0, true, false},
		{"empty string", `""`, 0, true, false},
		{"quoted timestamp", `"1609459200"`, 1609459200, false, false},
		{"quoted null", `"null"`, 0, true, false},
		{"invalid format", `"not-a-number"`, 0, false, true},
		{"negative timestamp", "-1", 0, false, true},
		{"exceeds max timestamp", "999999999999", 0, false, true},
		{"empty bytes", "", 0, false, true},
		{"float string", "1609459200.5", 0, false, true},
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

func TestNumericDateRoundTrip(t *testing.T) {
	timestamps := []int64{0, 1609459200, 253402300799}

	for _, ts := range timestamps {
		original := NewNumericDate(time.Unix(ts, 0).UTC())
		data, err := json.Marshal(&original)
		if err != nil {
			t.Fatalf("Failed to marshal timestamp %d: %v", ts, err)
		}

		var decoded NumericDate
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal %s: %v", string(data), err)
		}

		if decoded.Unix() != original.Unix() {
			t.Errorf("Round trip failed: original=%d, decoded=%d", original.Unix(), decoded.Unix())
		}
	}
}

func TestStringOrSliceUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantNil bool
	}{
		{"single string", `"api-v1"`, []string{"api-v1"}, false},
		{"string array", `["api-v1","api-v2"]`, []string{"api-v1", "api-v2"}, false},
		{"null value", `null`, nil, true},
		{"empty array", `[]`, []string{}, false},
		{"empty string", `""`, []string{""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sos StringOrSlice
			if err := json.Unmarshal([]byte(tt.input), &sos); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if tt.wantNil {
				if sos != nil {
					t.Errorf("Expected nil, got %v", sos)
				}
				return
			}

			if len(sos) != len(tt.want) {
				t.Fatalf("Length: got %d, want %d", len(sos), len(tt.want))
			}
			for i, v := range sos {
				if v != tt.want[i] {
					t.Errorf("Element %d: got %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestStringOrSliceUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"invalid JSON in string", `"unterminated`},
		{"invalid JSON in array", `[1,2,3]`},
		{"number instead of string/array", `123`},
		{"object instead of string/array", `{"key":"value"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sos StringOrSlice
			if err := json.Unmarshal([]byte(tt.input), &sos); err == nil {
				t.Error("Expected error")
			}
		})
	}
}

func TestRegisteredClaimsFields(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "test_user", Username: "test"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Token validation failed: %v", err)
	}

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

func TestSigningMethodClassification(t *testing.T) {
	tests := []struct {
		name        string
		method      SigningMethod
		isHMAC      bool
		isAsym      bool
		isValid     bool
	}{
		{"HS256", SigningMethodHS256, true, false, true},
		{"HS384", SigningMethodHS384, true, false, true},
		{"HS512", SigningMethodHS512, true, false, true},
		{"RS256", SigningMethodRS256, false, true, true},
		{"RS384", SigningMethodRS384, false, true, true},
		{"RS512", SigningMethodRS512, false, true, true},
		{"ES256", SigningMethodES256, false, true, true},
		{"ES384", SigningMethodES384, false, true, true},
		{"ES512", SigningMethodES512, false, true, true},
		{"Invalid", SigningMethod("INVALID"), false, false, false},
		{"Empty", SigningMethod(""), false, false, false},
		{"None", SigningMethod("none"), false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.method.isHMAC() != tt.isHMAC {
				t.Errorf("isHMAC() = %v, want %v", tt.method.isHMAC(), tt.isHMAC)
			}
			if tt.method.isAsymmetric() != tt.isAsym {
				t.Errorf("isAsymmetric() = %v, want %v", tt.method.isAsymmetric(), tt.isAsym)
			}
			if tt.method.isValid() != tt.isValid {
				t.Errorf("isValid() = %v, want %v", tt.method.isValid(), tt.isValid)
			}
		})
	}
}
