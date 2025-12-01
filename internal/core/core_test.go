package core

import (
	"strings"
	"testing"

	"github.com/cybergodev/jwt/internal/signing"
)

func TestNewTokenWithClaims(t *testing.T) {
	method := signing.GetHMACMethod("HS256")
	claims := map[string]any{
		"sub": "user123",
		"exp": 1234567890,
	}

	token := NewTokenWithClaims(method, claims)
	if token == nil {
		t.Fatal("NewTokenWithClaims returned nil")
	}

	if token.Header["typ"] != "JWT" {
		t.Errorf("Expected typ=JWT, got %v", token.Header["typ"])
	}

	if token.Header["alg"] != "HS256" {
		t.Errorf("Expected alg=HS256, got %v", token.Header["alg"])
	}

	if token.Claims == nil {
		t.Error("Claims not set correctly")
	}

	if token.Method != method {
		t.Error("Method not set correctly")
	}
}

func TestFastSplit3(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		sep    byte
		wantP1 string
		wantP2 string
		wantP3 string
		wantOk bool
	}{
		{
			name:   "valid JWT format",
			input:  "header.payload.signature",
			sep:    '.',
			wantP1: "header",
			wantP2: "payload",
			wantP3: "signature",
			wantOk: true,
		},
		{
			name:   "only one separator",
			input:  "header.payload",
			sep:    '.',
			wantOk: false,
		},
		{
			name:   "no separator",
			input:  "headerPayloadSignature",
			sep:    '.',
			wantOk: false,
		},
		{
			name:   "empty string",
			input:  "",
			sep:    '.',
			wantOk: false,
		},
		{
			name:   "extra separators",
			input:  "a.b.c.d",
			sep:    '.',
			wantP1: "a",
			wantP2: "b",
			wantP3: "c.d",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, p2, p3, ok := fastSplit3(tt.input, tt.sep)
			if ok != tt.wantOk {
				t.Errorf("fastSplit3() ok = %v, want %v", ok, tt.wantOk)
			}
			if ok && (p1 != tt.wantP1 || p2 != tt.wantP2 || p3 != tt.wantP3) {
				t.Errorf("fastSplit3() = (%q, %q, %q), want (%q, %q, %q)",
					p1, p2, p3, tt.wantP1, tt.wantP2, tt.wantP3)
			}
		})
	}
}

func TestParseWithClaimsErrors(t *testing.T) {
	tests := []struct {
		name        string
		tokenString string
		wantErr     string
	}{
		{
			name:        "empty token",
			tokenString: "",
			wantErr:     "empty token",
		},
		{
			name:        "token too large",
			tokenString: strings.Repeat("a", 9000),
			wantErr:     "token too large",
		},
		{
			name:        "invalid format - no dots",
			tokenString: "invalidtoken",
			wantErr:     "invalid token format",
		},
		{
			name:        "invalid format - one dot",
			tokenString: "header.payload",
			wantErr:     "invalid token format",
		},
		{
			name:        "part too large",
			tokenString: strings.Repeat("a", 5000) + "." + "b" + "." + "c",
			wantErr:     "invalid segment length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := make(map[string]any)
			keyFunc := func(*Core) (any, error) {
				return []byte("test-secret-key"), nil
			}

			_, err := ParseWithClaims(tt.tokenString, claims, keyFunc)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestParseUnverifiedErrors(t *testing.T) {
	tests := []struct {
		name        string
		tokenString string
		wantErr     string
	}{
		{
			name:        "empty token",
			tokenString: "",
			wantErr:     "empty token",
		},
		{
			name:        "token too large",
			tokenString: strings.Repeat("a", 9000),
			wantErr:     "token too large",
		},
		{
			name:        "invalid format",
			tokenString: "invalid",
			wantErr:     "invalid token format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := make(map[string]any)
			_, _, err := ParseUnverified(tt.tokenString, claims)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestIsInsecureAlgorithm(t *testing.T) {
	tests := []struct {
		alg        string
		wantSecure bool
	}{
		{"", true},
		{"none", true},
		{"NONE", true},
		{"None", true},
		{"HS1", true},
		{"RS1", true},
		{"ES1", true},
		{"HS224", true},
		{"RS224", true},
		{"ES224", true},
		{"NULL", true},
		{"null", true},
		{"PLAIN", true},
		{"plain", true},
		{"HS256", false},
		{"HS384", false},
		{"HS512", false},
		{"  none  ", true},
		{"  HS256  ", false},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			result := isInsecureAlgorithm(tt.alg)
			if result != tt.wantSecure {
				t.Errorf("isInsecureAlgorithm(%q) = %v, want %v", tt.alg, result, tt.wantSecure)
			}
		})
	}
}

func TestGenerateTokenIDFast(t *testing.T) {
	// Test basic generation
	id1 := GenerateTokenIDFast()
	if len(id1) != 4+TokenIDLength*2 {
		t.Errorf("Expected length %d, got %d", 4+TokenIDLength*2, len(id1))
	}

	if !strings.HasPrefix(id1, "tok_") {
		t.Errorf("Expected prefix 'tok_', got %q", id1[:4])
	}

	// Test uniqueness
	id2 := GenerateTokenIDFast()
	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}

	// Test multiple generations
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateTokenIDFast()
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestCoreSignedString(t *testing.T) {
	method := signing.GetHMACMethod("HS256")
	claims := map[string]any{
		"sub": "user123",
		"exp": 1234567890,
	}

	token := NewTokenWithClaims(method, claims)
	key := []byte("test-secret-key-with-sufficient-length-32bytes")

	tokenString, err := token.SignedString(key)
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

func TestDecodeSegmentErrors(t *testing.T) {
	tests := []struct {
		name    string
		segment string
		wantErr bool
	}{
		{
			name:    "empty segment",
			segment: "",
			wantErr: true,
		},
		{
			name:    "segment too large",
			segment: strings.Repeat("a", 5000),
			wantErr: true,
		},
		{
			name:    "invalid base64",
			segment: "!!!invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dest map[string]any
			err := DecodeSegment(tt.segment, &dest)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeSegment() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseWithClaimsInsecureAlgorithm(t *testing.T) {
	// Create a token with "none" algorithm (should be rejected)
	tokenString := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0."

	claims := make(map[string]any)
	keyFunc := func(*Core) (any, error) {
		return []byte("test-key"), nil
	}

	_, err := ParseWithClaims(tokenString, &claims, keyFunc)
	if err == nil {
		t.Error("Expected error for insecure algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "insecure") && !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("Expected 'insecure' or 'algorithm' in error, got: %v", err)
	}
}

func TestParseUnverifiedInsecureAlgorithm(t *testing.T) {
	// Token with "none" algorithm
	tokenString := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0."

	claims := make(map[string]any)
	_, _, err := ParseUnverified(tokenString, claims)
	if err == nil {
		t.Error("Expected error for insecure algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "insecure") {
		t.Errorf("Expected 'insecure' in error, got: %v", err)
	}
}
