package signing

import (
	"crypto"
	"strings"
	"testing"
)

func TestGetHMACMethod(t *testing.T) {
	tests := []struct {
		alg      string
		wantNil  bool
		wantHash crypto.Hash
	}{
		{"HS256", false, crypto.SHA256},
		{"HS384", false, crypto.SHA384},
		{"HS512", false, crypto.SHA512},
		{"HS128", true, 0},
		{"invalid", true, 0},
		{"", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method := GetHMACMethod(tt.alg)
			if tt.wantNil {
				if method != nil {
					t.Errorf("Expected nil for %q, got %v", tt.alg, method)
				}
			} else {
				if method == nil {
					t.Fatalf("Expected method for %q, got nil", tt.alg)
				}
				if method.Alg() != tt.alg {
					t.Errorf("Expected alg %q, got %q", tt.alg, method.Alg())
				}
				if method.Hash() != tt.wantHash {
					t.Errorf("Expected hash %v, got %v", tt.wantHash, method.Hash())
				}
			}
		})
	}
}

func TestHMACSignAndVerify(t *testing.T) {
	key := []byte("test-secret-key-with-sufficient-length")
	signingString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0"

	tests := []struct {
		alg string
	}{
		{"HS256"},
		{"HS384"},
		{"HS512"},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method := GetHMACMethod(tt.alg)
			if method == nil {
				t.Fatalf("GetHMACMethod(%q) returned nil", tt.alg)
			}

			// Check if hash is available
			if !method.Hash().Available() {
				t.Skipf("Hash function %v not available on this platform", method.Hash())
			}

			// Sign
			signature, err := method.Sign(signingString, key)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if signature == "" {
				t.Error("Sign returned empty signature")
			}

			// Verify with correct signature
			err = method.Verify(signingString, signature, key)
			if err != nil {
				t.Errorf("Verify failed: %v", err)
			}

			// Verify with wrong signature
			wrongSignature := "invalid-signature"
			err = method.Verify(signingString, wrongSignature, key)
			if err == nil {
				t.Error("Expected error for invalid signature, got nil")
			}

			// Verify with wrong key
			wrongKey := []byte("wrong-key-different-from-original")
			err = method.Verify(signingString, signature, wrongKey)
			if err == nil {
				t.Error("Expected error for wrong key, got nil")
			}
		})
	}
}

func TestHMACSignInvalidKey(t *testing.T) {
	method := GetHMACMethod("HS256")
	signingString := "test.data"

	// Test with non-[]byte key
	_, err := method.Sign(signingString, "string-key")
	if err == nil {
		t.Error("Expected error for non-[]byte key, got nil")
	}
	if !strings.Contains(err.Error(), "must be []byte") {
		t.Errorf("Expected 'must be []byte' in error, got: %v", err)
	}
}

func TestHMACVerifyInvalidKey(t *testing.T) {
	method := GetHMACMethod("HS256")
	signingString := "test.data"
	signature := "valid-signature"

	// Test with non-[]byte key
	err := method.Verify(signingString, signature, "string-key")
	if err == nil {
		t.Error("Expected error for non-[]byte key, got nil")
	}
	if !strings.Contains(err.Error(), "must be []byte") {
		t.Errorf("Expected 'must be []byte' in error, got: %v", err)
	}
}

func TestSignedString(t *testing.T) {
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"sub": "user123",
		"exp": 1234567890,
	}
	method := GetHMACMethod("HS256")
	key := []byte("test-secret-key-with-sufficient-length")

	tokenString, err := SignedString(header, claims, method, key)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}

	if tokenString == "" {
		t.Error("SignedString returned empty string")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(parts))
	}
}

func TestSignedStringInvalidHeader(t *testing.T) {
	// Header with non-serializable value
	header := map[string]any{
		"alg":     "HS256",
		"invalid": make(chan int), // channels can't be marshaled
	}
	claims := map[string]any{"sub": "test"}
	method := GetHMACMethod("HS256")
	key := []byte("test-key")

	_, err := SignedString(header, claims, method, key)
	if err == nil {
		t.Error("Expected error for invalid header, got nil")
	}
}

func TestSignedStringInvalidClaims(t *testing.T) {
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	// Claims with non-serializable value
	claims := map[string]any{
		"sub":     "test",
		"invalid": make(chan int),
	}
	method := GetHMACMethod("HS256")
	key := []byte("test-key")

	_, err := SignedString(header, claims, method, key)
	if err == nil {
		t.Error("Expected error for invalid claims, got nil")
	}
}

func TestGetInternalSigningMethod(t *testing.T) {
	tests := []struct {
		alg     string
		wantErr bool
	}{
		{"HS256", false},
		{"HS384", false},
		{"HS512", false},
		{"", true},
		{"none", true},
		{"RS256", true},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(tt.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInternalSigningMethod(%q) error = %v, wantErr %v", tt.alg, err, tt.wantErr)
			}
			if !tt.wantErr && method == nil {
				t.Error("Expected method, got nil")
			}
			if tt.wantErr && method != nil {
				t.Error("Expected nil method for error case")
			}
		})
	}
}

func TestHMACVerifyInvalidSignature(t *testing.T) {
	method := GetHMACMethod("HS256")
	key := []byte("test-secret-key")
	signingString := "test.data"

	// Test with invalid base64 signature
	err := method.Verify(signingString, "!!!invalid-base64!!!", key)
	if err == nil {
		t.Error("Expected error for invalid base64 signature, got nil")
	}
}

func TestHMACMethodAlg(t *testing.T) {
	tests := []struct {
		alg  string
		want string
	}{
		{"HS256", "HS256"},
		{"HS384", "HS384"},
		{"HS512", "HS512"},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method := GetHMACMethod(tt.alg)
			if method.Alg() != tt.want {
				t.Errorf("Alg() = %q, want %q", method.Alg(), tt.want)
			}
		})
	}
}

func TestHMACMethodHash(t *testing.T) {
	tests := []struct {
		alg  string
		want crypto.Hash
	}{
		{"HS256", crypto.SHA256},
		{"HS384", crypto.SHA384},
		{"HS512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method := GetHMACMethod(tt.alg)
			if method.Hash() != tt.want {
				t.Errorf("Hash() = %v, want %v", method.Hash(), tt.want)
			}
		})
	}
}
